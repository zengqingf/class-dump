//
//  CDLCChainedFixups.m
//  classdumpios
//
//  Created by kevinbradley on 6/26/22.
//

// Massive thanks to this repo and everything in it to help me get a better handle on DYLD_CHAINED_FIXUPS https://github.com/qyang-nj/llios/blob/main/dynamic_linking/chained_fixups.md

/**
 
 A few notes about this class, it was originally based around how binding an rebasing worked in CDLCDyldInfo
 therefore a similar paradigm is kept utilizing the _symbolNamesByAddress
 
 
 
 */

#import "CDLCChainedFixups.h"
#include <mach-o/loader.h>
#include <mach-o/fixup-chains.h>
#import "CDLCSegment.h"
#import "CDLCSymbolTable.h"
#import "CDSymbol.h"
#import "CDLCDylib.h"

@implementation CDLCChainedFixups {
    struct linkedit_data_command _linkeditDataCommand;
    NSData *_linkeditData;
    NSUInteger _ptrSize;
    NSMutableDictionary *_symbolNamesByAddress;
    NSMutableDictionary *_based;
    NSMutableDictionary *_imports;
}


static void printChainedFixupsHeader(struct dyld_chained_fixups_header *header) {
    const char *imports_format = NULL;
    switch (header->imports_format) {
        case DYLD_CHAINED_IMPORT: imports_format = "DYLD_CHAINED_IMPORT"; break;
        case DYLD_CHAINED_IMPORT_ADDEND: imports_format = "DYLD_CHAINED_IMPORT_ADDEND"; break;
        case DYLD_CHAINED_IMPORT_ADDEND64: imports_format = "DYLD_CHAINED_IMPORT_ADDEND64"; break;
    }
    if ([CDClassDump printFixupData]){
        fprintf(stderr,"  CHAINED FIXUPS HEADER\n");
        fprintf(stderr,"    fixups_version : %d\n", header->fixups_version);
        fprintf(stderr,"    starts_offset  : %#4x (%d)\n", header->starts_offset, header->starts_offset);
        fprintf(stderr,"    imports_offset : %#4x (%d)\n", header->imports_offset, header->imports_offset);
        fprintf(stderr,"    symbols_offset : %#4x (%d)\n", header->symbols_offset, header->symbols_offset);
        fprintf(stderr,"    imports_count  : %d\n", header->imports_count);
        fprintf(stderr,"    imports_format : %d (%s)\n", header->imports_format, imports_format);
        fprintf(stderr,"    symbols_format : %d (%s)\n", header->symbols_format,
                (header->symbols_format == 0 ? "UNCOMPRESSED" : "ZLIB COMPRESSED"));
        fprintf(stderr,"\n");
    }
    
}

- (uint64_t)signExtendedAddend:(struct dyld_chained_ptr_64_bind)fixupBind {
    
    uint64_t addend27     = fixupBind.addend;
    uint64_t top8Bits     = addend27 & 0x00007F80000ULL;
    uint64_t bottom19Bits = addend27 & 0x0000007FFFFULL;
    uint64_t newValue     = (top8Bits << 13) | (((uint64_t)(bottom19Bits << 37) >> 37) & 0x00FFFFFFFFFFFFFF);
    return newValue;
}

//symbol_offset_address = (virtual_symbol_address - containing_macho_section_virtual_address) + contain_macho_section_file_offset

- (void)processFixupsInPage:(uint8_t *)base fixupBase:(uint8_t*)fixupBase header:(struct dyld_chained_fixups_header *)header startsIn:(struct dyld_chained_starts_in_segment *)segment page:(int)pageIndex {
    uint32_t chain = (uint32_t)segment->segment_offset + segment->page_size * pageIndex + segment->page_start[pageIndex];
    bool done = false;
    int count = 0;
    while (!done) {
        if (segment->pointer_format == DYLD_CHAINED_PTR_64
            || segment->pointer_format == DYLD_CHAINED_PTR_64_OFFSET) {
            struct dyld_chained_ptr_64_bind bind = *(struct dyld_chained_ptr_64_bind *)(base + chain);
            if (bind.bind) { //we are binding a symbol
                
                struct dyld_chained_import import = ((struct dyld_chained_import *)(fixupBase + header->imports_offset))[bind.ordinal];
                char *symbol = (char *)(fixupBase + header->symbols_offset + import.name_offset);
                uint64_t peeked = [self.machOFile peekPtrAtOffset:chain ptrSize:_ptrSize];
                uint64_t raw = _OSSwapInt64(peeked); //honestly not sure why byte swapping is 'necessary' here, but it works.

                if ([CDClassDump printFixupData]){
                    NSString *lib = _imports[[NSString stringWithUTF8String:symbol]];
                    fprintf(stderr,"        0x%08x RAW: %#010llx  BIND     ordinal: %d   addend: %d    dylib: %s   (%s)\n",
                            chain, raw, bind.ordinal, bind.addend, [lib UTF8String], symbol);
                }
                [self bindAddress:raw symbolName:symbol];
            } else {
                // rebase 0x%08lx
                struct dyld_chained_ptr_64_rebase rebase = *(struct dyld_chained_ptr_64_rebase *)&bind;
                
                uint64_t raw = [self.machOFile peekPtrAtOffset:chain ptrSize:_ptrSize];
                uint64_t unpackedTarget = (((uint64_t)rebase.high8) << 56) | (uint64_t)(rebase.target);
                // The DYLD_CHAINED_PTR_64 target is vmaddr, but
                // DYLD_CHAINED_PTR_64_OFFSET target is vmoffset. Need to add preferredLoadAddress to find it! -- major missing piece to getting this working.
                if (segment->pointer_format == DYLD_CHAINED_PTR_64_OFFSET) {
                    unpackedTarget += self.machOFile.preferredLoadAddress;
                    //ODLog(@"unpackedTarget adjusted", unpackedTarget);
                }
                if ([CDClassDump printFixupData]){
                    fprintf(stderr,"        %#010x RAW: %#010llx REBASE   target: %#010llx   high8: %#010x\n",
                            chain, raw, unpackedTarget, rebase.high8);
                }
                
                [self rebaseAddress:raw target:unpackedTarget];
            }
            
            if (bind.next == 0) {
                done = true;
            } else {
                chain += bind.next * 4;
            }
            
        } else {
            printf("Unsupported pointer format: 0x%x", segment->pointer_format);
            break;
        }
        count++;
    }
}

- (NSString *) getDylibName:(uint16_t) dylibOrdinal {
    NSString *dylibName = nil;

    switch (dylibOrdinal) {
        case (uint8_t)BIND_SPECIAL_DYLIB_SELF:
            dylibName = @"self";
            break;
        case (uint8_t)BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE:
            dylibName = @"main executable";
            break;
        case (uint8_t)BIND_SPECIAL_DYLIB_FLAT_LOOKUP:
            dylibName = @"flat lookup";
            break;
        case (uint8_t)BIND_SPECIAL_DYLIB_WEAK_LOOKUP:
            dylibName = @"weak lookup";
            break;
        default:
            dylibName = [self getDylibNameByOrdinal:dylibOrdinal baseName:true];
            break;
    }
    return [NSString stringWithFormat:@"%lu (%@)", dylibOrdinal, dylibName];
}

- (NSPredicate *)dyldPredicate {
    NSPredicate *pred = [NSPredicate predicateWithBlock:^BOOL(id  _Nullable evaluatedObject, NSDictionary<NSString *,id> * _Nullable bindings) {
        if ([evaluatedObject isKindOfClass:[CDLCDylib class]]){
            return true;
        } else {
            return false;
        }
    }];
    return pred;
}

- (CDLCDylib *)dylibCommandForOrdinal:(NSInteger)ordinal {
    NSArray <CDLCDylib *> *dylibCommands = [self.machOFile.loadCommands filteredArrayUsingPredicate:[self dyldPredicate]];
    if (dylibCommands.count > ordinal){
        return dylibCommands[ordinal];
    }
    return nil;
}

- (NSString *)getDylibNameByOrdinal:(NSInteger)ordinal baseName:(BOOL)basename {
    if (ordinal > 0 && ordinal <= MAX_LIBRARY_ORDINAL) { // 0 ~ 253
        CDLCDylib *dylibCmd = [self dylibCommandForOrdinal:ordinal - 1];
        //InfoLog(@"found dylibCmd: %@ for ordinal: %lu", dylibCmd, ordinal);
        if (basename) {
            return dylibCmd.path.lastPathComponent;
        }
        return dylibCmd.path;
    } else if (ordinal == DYNAMIC_LOOKUP_ORDINAL) { // 254
        return @"dynamic lookup";
    } else if (ordinal == EXECUTABLE_ORDINAL) { // 255
        return @"exectuable";
    }
    return @"invalid ordinal";
}

- (void)printImports:(struct dyld_chained_fixups_header *)header {
    if([CDClassDump printFixupData]){
        fprintf(stderr,"  IMPORTS\n");
    }
    int importCount = 0;
    for (int i = 0; i < header->imports_count; ++i) {
        struct dyld_chained_import import =
            ((struct dyld_chained_import *)((uint8_t *)header + header->imports_offset))[i];
        NSString *dylibName = [self getDylibNameByOrdinal:import.lib_ordinal baseName:true];
        //NSNumber *ordinalNumber = [NSNumber numberWithUnsignedInteger:import.lib_ordinal];
        char * symbol = (char *)((uint8_t *)header + header->symbols_offset + import.name_offset);
        _imports[[NSString stringWithUTF8String:symbol]] = dylibName;
        
        if([CDClassDump printFixupData]){
            fprintf(stderr,"    [%d] lib_ordinal: %-22s   weak_import: %d   name_offset: %d (%s)\n",
                   i, [[self getDylibName:import.lib_ordinal] UTF8String], import.weak_import, import.name_offset,
                    symbol);
        }
        importCount++;
    }
    if([CDClassDump printFixupData]){
        fprintf(stderr,"\n");
        InfoLog(@"imports: %@", _imports);
    }
}

static void formatPointerFormat(uint16_t pointer_format, char *formatted) {
    switch(pointer_format) {
        case DYLD_CHAINED_PTR_ARM64E: strcpy(formatted, "DYLD_CHAINED_PTR_ARM64E"); break;
        case DYLD_CHAINED_PTR_64: strcpy(formatted, "DYLD_CHAINED_PTR_64"); break;
        case DYLD_CHAINED_PTR_32: strcpy(formatted, "DYLD_CHAINED_PTR_32"); break;
        case DYLD_CHAINED_PTR_32_CACHE: strcpy(formatted, "DYLD_CHAINED_PTR_32_CACHE"); break;
        case DYLD_CHAINED_PTR_32_FIRMWARE: strcpy(formatted, "DYLD_CHAINED_PTR_32_FIRMWARE"); break;
        case DYLD_CHAINED_PTR_64_OFFSET: strcpy(formatted, "DYLD_CHAINED_PTR_64_OFFSET"); break;
        case DYLD_CHAINED_PTR_ARM64E_KERNEL: strcpy(formatted, "DYLD_CHAINED_PTR_ARM64E_KERNEL"); break;
        case DYLD_CHAINED_PTR_64_KERNEL_CACHE: strcpy(formatted, "DYLD_CHAINED_PTR_64_KERNEL_CACHE"); break;
        case DYLD_CHAINED_PTR_ARM64E_USERLAND: strcpy(formatted, "DYLD_CHAINED_PTR_ARM64E_USERLAND"); break;
        case DYLD_CHAINED_PTR_ARM64E_FIRMWARE: strcpy(formatted, "DYLD_CHAINED_PTR_ARM64E_FIRMWARE"); break;
        case DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE: strcpy(formatted, "DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE"); break;
        case DYLD_CHAINED_PTR_ARM64E_USERLAND24: strcpy(formatted, "DYLD_CHAINED_PTR_ARM64E_USERLAND24"); break;
        default: strcpy(formatted, "UNKNOWN");
    }
}

- (id)initWithDataCursor:(CDMachOFileDataCursor *)cursor; {
    if ((self = [super initWithDataCursor:cursor])) {
        _linkeditDataCommand.cmd     = [cursor readInt32];
        _linkeditDataCommand.cmdsize = [cursor readInt32];
        
        _linkeditDataCommand.dataoff  = [cursor readInt32];
        _linkeditDataCommand.datasize = [cursor readInt32];
        _ptrSize = [[cursor machOFile] ptrSize];
        _symbolNamesByAddress = [NSMutableDictionary new];
        _based = [NSMutableDictionary new];
        _imports = [NSMutableDictionary new];
    }
    
    return self;
}

#pragma mark -

- (uint32_t)cmd; {
    return _linkeditDataCommand.cmd;
}

- (uint32_t)cmdsize; {
    return _linkeditDataCommand.cmdsize;
}

- (NSData *)linkeditData; {
    if (_linkeditData == NULL) {
        _linkeditData = [[NSData alloc] initWithBytes:[self.machOFile bytesAtOffset:_linkeditDataCommand.dataoff] length:_linkeditDataCommand.datasize];
    }
    
    return _linkeditData;
}

- (NSString *)externalClassNameForAddress:(NSUInteger)address; {
    NSString *str = [self symbolNameForAddress:address];
    
    if (str != nil) {
        if ([str hasPrefix:ObjCClassSymbolPrefix]) {
            return [str substringFromIndex:[ObjCClassSymbolPrefix length]];
        } else {
            DLog(@"Warning: Unknown prefix on symbol name... %@ (addr %lx)", str, address);
            return str;
        }
    }
    
    return nil;
}

- (NSString *)symbolNameForAddress:(NSUInteger)address; {
    return [_symbolNamesByAddress objectForKey:[NSNumber numberWithUnsignedInteger:address]];
}

- (NSUInteger)rebaseTargetFromAddress:(NSUInteger)address {
    return [self rebaseTargetFromAddress:address adjustment:0];
}

//refactor, the adjustment should never be needed again.
- (NSUInteger)rebaseTargetFromAddress:(NSUInteger)address adjustment:(NSUInteger)adj {
    InfoLog(@"%s : %#010llx (%lu)", _cmds, address-adj, address-adj);
    NSNumber *key = [NSNumber numberWithUnsignedInteger:address-adj]; // I don't think 32-bit will dump 64-bit stuff.
    return [_based[key] unsignedIntegerValue];
}

- (void)rebaseAddress:(uint64_t)address target:(uint64_t)target {
    NSNumber *key = [NSNumber numberWithUnsignedInteger:address]; // I don't think 32-bit will dump 64-bit stuff.
    NSNumber *val = [NSNumber numberWithUnsignedInteger:target];
    _based[key] = val;
}

- (void)bindAddress:(uint64_t)address symbolName:(const char *)symbolName {
    NSNumber *key = [NSNumber numberWithUnsignedInteger:address]; // I don't think 32-bit will dump 64-bit stuff.
    NSString *str = [[NSString alloc] initWithUTF8String:symbolName];
    _symbolNamesByAddress[key] = str;
}

//obsolete, leaving in here in case i ever need those other details and save this in a less hacky fashion
- (void)bindAddress:(uint64_t)address type:(uint8_t)type symbolName:(const char *)symbolName flags:(uint8_t)flags
             addend:(int64_t)addend libraryOrdinal:(int64_t)libraryOrdinal; {
#if 0
    VerboseLog(@"    Bind address: %016lx, type: 0x%02x, flags: %02x, addend: %016lx, libraryOrdinal: %ld, symbolName: %s",
               address, type, flags, addend, libraryOrdinal, symbolName);
#endif
    
    NSNumber *key = [NSNumber numberWithUnsignedInteger:address]; // I don't think 32-bit will dump 64-bit stuff.
    NSString *str = [[NSString alloc] initWithUTF8String:symbolName];
    _symbolNamesByAddress[key] = str;
}

- (void)machOFileDidReadLoadCommands:(CDMachOFile *)machOFile; {
    //[super machOFileDidReadLoadCommands:machOFile];
    uint8_t *fixup_base = (uint8_t *)[[self linkeditData] bytes];
    struct dyld_chained_fixups_header *header = (struct dyld_chained_fixups_header *)fixup_base;
    printChainedFixupsHeader(header);
    [self printImports:header];
    struct dyld_chained_starts_in_image *starts_in_image =
    (struct dyld_chained_starts_in_image *)(fixup_base + header->starts_offset);
    
    uint32_t *offsets = starts_in_image->seg_info_offset;
    for (int i = 0; i < starts_in_image->seg_count; ++i) {
        CDLCSegment *segCmd = self.machOFile.segments[i];
        //struct segment_command_64 *segCmd = machoBinary.segmentCommands[i];
        if ([CDClassDump printFixupData]) {
            fprintf(stderr,"  SEGMENT %.16s (offset: %d)\n", [segCmd.name UTF8String], offsets[i]);
        }
        if (offsets[i] == 0) {
            if ([CDClassDump printFixupData]) {
                fprintf(stderr,"\n");
            }
            continue;
        }
        
        struct dyld_chained_starts_in_segment* startsInSegment = (struct dyld_chained_starts_in_segment*)(fixup_base + header->starts_offset + offsets[i]);
        char formatted_pointer_format[256];
        formatPointerFormat(startsInSegment->pointer_format, formatted_pointer_format);
        if ([CDClassDump printFixupData]){
            fprintf(stderr,"    size: %d\n", startsInSegment->size);
            fprintf(stderr,"    page_size: 0x%x\n", startsInSegment->page_size);
            fprintf(stderr,"    pointer_format: %d (%s)\n", startsInSegment->pointer_format, formatted_pointer_format);
            fprintf(stderr,"    segment_offset: 0x%llx\n", startsInSegment->segment_offset);
            fprintf(stderr,"    max_valid_pointer: %d\n", startsInSegment->max_valid_pointer);
            fprintf(stderr,"    page_count: %d\n", startsInSegment->page_count);
            fprintf(stderr,"    page_start: %d\n", startsInSegment-> page_start[0]);
        }
        uint16_t *page_starts = startsInSegment->page_start;
        uint16_t maxPageNum = UINT16_MAX;
        int pageCount = 0;
        for (int j = 0; j < MIN(startsInSegment->page_count, maxPageNum); ++j) {
            if ([CDClassDump printFixupData]){
                fprintf(stderr,"      PAGE %d (offset: %d)\n", j, page_starts[j]);
            }
            if (page_starts[j] == DYLD_CHAINED_PTR_START_NONE) { continue; }
            
            [self processFixupsInPage:(uint8_t *)[self.machOFile bytes] fixupBase:fixup_base header:header startsIn:startsInSegment page:j];
            
            pageCount++;
            if ([CDClassDump printFixupData]){
                fprintf(stderr,"\n");
            }
        }
        if ([CDClassDump printFixupData]){
            DLog(@"symbolNamesByAddress: %@", _symbolNamesByAddress);
            DLog(@"based: %@", _based);
        }
    }
}


@end
