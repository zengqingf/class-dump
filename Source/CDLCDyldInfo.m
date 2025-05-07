// -*- mode: ObjC -*-

//  This file is part of class-dump, a utility for examining the Objective-C segment of Mach-O files.
//  Copyright (C) 1997-2019 Steve Nygard.

#import "CDLCDyldInfo.h"

#import "CDMachOFile.h"

#import "CDLCSegment.h"
#import "ULEB128.h"

#ifdef DEBUG
static BOOL debugBindOps = YES;
static BOOL debugExportedSymbols = YES;
#else
static BOOL debugBindOps = NO;
static BOOL debugExportedSymbols = NO;
#endif

// Can use dyldinfo(1) to view info.

static NSString *CDRebaseTypeDescription(uint8_t type)
{
    switch (type) {
        case REBASE_TYPE_POINTER:         return @"Pointer";
        case REBASE_TYPE_TEXT_ABSOLUTE32: return @"Absolute 32";
        case REBASE_TYPE_TEXT_PCREL32:    return @"PC rel 32";
    }

    return @"Unknown";
}

static NSString *CDBindTypeDescription(uint8_t type)
{
    switch (type) {
        case REBASE_TYPE_POINTER:         return @"Pointer";
        case REBASE_TYPE_TEXT_ABSOLUTE32: return @"Absolute 32";
        case REBASE_TYPE_TEXT_PCREL32:    return @"PC rel 32";
    }

    return @"Unknown";
}

@interface CDLCDyldInfo ()
@end

#pragma mark -

// Needs access to: list of segments

@implementation CDLCDyldInfo
{
    struct dyld_info_command _dyldInfoCommand;
    
    NSUInteger _ptrSize;
    NSMutableDictionary *_symbolNamesByAddress;
}

- (id)initWithDataCursor:(CDMachOFileDataCursor *)cursor;
{
    if ((self = [super initWithDataCursor:cursor])) {
        _dyldInfoCommand.cmd     = [cursor readInt32];
        _dyldInfoCommand.cmdsize = [cursor readInt32];
        
        _dyldInfoCommand.rebase_off     = [cursor readInt32];
        _dyldInfoCommand.rebase_size    = [cursor readInt32];
        _dyldInfoCommand.bind_off       = [cursor readInt32];
        _dyldInfoCommand.bind_size      = [cursor readInt32];
        _dyldInfoCommand.weak_bind_off  = [cursor readInt32];
        _dyldInfoCommand.weak_bind_size = [cursor readInt32];
        _dyldInfoCommand.lazy_bind_off  = [cursor readInt32];
        _dyldInfoCommand.lazy_bind_size = [cursor readInt32];
        _dyldInfoCommand.export_off     = [cursor readInt32];
        _dyldInfoCommand.export_size    = [cursor readInt32];
        
#if 0
        DLog(@"       cmdsize: %08x", _dyldInfoCommand.cmdsize);
        DLog(@"    rebase_off: %08x", _dyldInfoCommand.rebase_off);
        DLog(@"   rebase_size: %08x", _dyldInfoCommand.rebase_size);
        DLog(@"      bind_off: %08x", _dyldInfoCommand.bind_off);
        DLog(@"     bind_size: %08x", _dyldInfoCommand.bind_size);
        DLog(@" weak_bind_off: %08x", _dyldInfoCommand.weak_bind_off);
        DLog(@"weak_bind_size: %08x", _dyldInfoCommand.weak_bind_size);
        DLog(@" lazy_bind_off: %08x", _dyldInfoCommand.lazy_bind_off);
        DLog(@"lazy_bind_size: %08x", _dyldInfoCommand.lazy_bind_size);
        DLog(@"    export_off: %08x", _dyldInfoCommand.export_off);
        DLog(@"   export_size: %08x", _dyldInfoCommand.export_size);
#endif
        
        _ptrSize = [[cursor machOFile] ptrSize];
        
        _symbolNamesByAddress = [[NSMutableDictionary alloc] init];
    }

    return self;
}

#pragma mark -

- (void)machOFileDidReadLoadCommands:(CDMachOFile *)machOFile;
{
    if ([CDClassDump isVerbose]) {
        [self logRebaseInfo];
    }
    [self parseBindInfo];
    [self parseWeakBindInfo];
    if ([CDClassDump isVerbose]) {
        [self logLazyBindInfo];
        [self logExportedSymbols];
    }
    
    VerboseLog(@"symbolNamesByAddress: %@", _symbolNamesByAddress);
}

#pragma mark -

- (uint32_t)cmd;
{
    return _dyldInfoCommand.cmd;
}

- (uint32_t)cmdsize;
{
    return _dyldInfoCommand.cmdsize;
}

- (NSString *)symbolNameForAddress:(NSUInteger)address;
{
    return [_symbolNamesByAddress objectForKey:[NSNumber numberWithUnsignedInteger:address]];
}

#pragma mark - Rebasing

// address, slide, type
// slide is constant throughout the loop
- (void)logRebaseInfo;
{
    BOOL isDone = NO;
    NSUInteger rebaseCount = 0;

    NSArray *segments = self.machOFile.segments;
    NSParameterAssert([segments count] > 0);

    uint64_t address = [segments[0] vmaddr];
    uint8_t type = 0;

    VerboseLog(@"----------------------------------------------------------------------");
    VerboseLog(@"rebase_off: %u, rebase_size: %u", _dyldInfoCommand.rebase_off, _dyldInfoCommand.rebase_size);
    const uint8_t *start = (uint8_t *)[self.machOFile.data bytes] + _dyldInfoCommand.rebase_off;
    const uint8_t *end = start + _dyldInfoCommand.rebase_size;

    VerboseLog(@"address: %016llx", address);
    const uint8_t *ptr = start;
    while ((ptr < end) && isDone == NO) {
        uint8_t immediate = *ptr & REBASE_IMMEDIATE_MASK;
        uint8_t opcode = *ptr & REBASE_OPCODE_MASK;
        ptr++;

        switch (opcode) {
            case REBASE_OPCODE_DONE:
                VerboseLog(@"REBASE_OPCODE: DONE");
                isDone = YES;
                break;
                
            case REBASE_OPCODE_SET_TYPE_IMM:
                VerboseLog(@"REBASE_OPCODE: SET_TYPE_IMM,                       type = 0x%x // %@", immediate, CDRebaseTypeDescription(immediate));
                type = immediate;
                break;
                
            case REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: {
                uint64_t val = read_uleb128(&ptr, end);
                
                VerboseLog(@"REBASE_OPCODE: SET_SEGMENT_AND_OFFSET_ULEB,        segment index: %u, offset: %016llx", immediate, val);
                NSParameterAssert(immediate < [segments count]);
                address = [segments[immediate] vmaddr] + val;
                VerboseLog(@"    address: %016llx", address);
                break;
            }
                
            case REBASE_OPCODE_ADD_ADDR_ULEB: {
                uint64_t val = read_uleb128(&ptr, end);
                
                VerboseLog(@"REBASE_OPCODE: ADD_ADDR_ULEB,                      addr += %016llx", val);
                address += val;
                VerboseLog(@"    address: %016llx", address);
                break;
            }
                
            case REBASE_OPCODE_ADD_ADDR_IMM_SCALED:
                // I expect sizeof(uintptr_t) == sizeof(uint64_t)
                VerboseLog(@"REBASE_OPCODE: ADD_ADDR_IMM_SCALED,                addr += %u * %lu", immediate, sizeof(uint64_t));
                address += immediate * _ptrSize;
                VerboseLog(@"    address: %016llx", address);
                break;
                
            case REBASE_OPCODE_DO_REBASE_IMM_TIMES: {
                VerboseLog(@"REBASE_OPCODE: DO_REBASE_IMM_TIMES,                count: %u", immediate);
                for (uint32_t index = 0; index < immediate; index++) {
                    [self rebaseAddress:address type:type];
                    address += _ptrSize;
                }
                rebaseCount += immediate;
                break;
            }
                
            case REBASE_OPCODE_DO_REBASE_ULEB_TIMES: {
                uint64_t count = read_uleb128(&ptr, end);
                
                VerboseLog(@"REBASE_OPCODE: DO_REBASE_ULEB_TIMES,               count: 0x%016llx", count);
                for (uint64_t index = 0; index < count; index++) {
                    [self rebaseAddress:address type:type];
                    address += _ptrSize;
                }
                rebaseCount += count;
                break;
            }
                
            case REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB: {
                uint64_t val = read_uleb128(&ptr, end);
                // --------------------------------------------------------:
                VerboseLog(@"REBASE_OPCODE: DO_REBASE_ADD_ADDR_ULEB,            addr += 0x%016llx", val);
                [self rebaseAddress:address type:type];
                address += _ptrSize + val;
                rebaseCount++;
                break;
            }
                
            case REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB: {
                uint64_t count = read_uleb128(&ptr, end);
                uint64_t skip = read_uleb128(&ptr, end);
                VerboseLog(@"REBASE_OPCODE: DO_REBASE_ULEB_TIMES_SKIPPING_ULEB, count: %016llx, skip: %016llx", count, skip);
                for (uint64_t index = 0; index < count; index++) {
                    [self rebaseAddress:address type:type];
                    address += _ptrSize + skip;
                }
                rebaseCount += count;
                break;
            }
                
            default:
                VerboseLog(@"Unknown opcode op: %x, imm: %x", opcode, immediate);
                exit(99);
        }
    }

    VerboseLog(@"    ptr: %p, end: %p, bytes left over: %ld", ptr, end, end - ptr);
    VerboseLog(@"    rebaseCount: %lu", rebaseCount);
    VerboseLog(@"----------------------------------------------------------------------");
}

- (void)rebaseAddress:(uint64_t)address type:(uint8_t)type;
{
    //VerboseLog(@"    Rebase 0x%016lx, type: %x (%@)", address, type, CDRebaseTypeString(type));
}

#pragma mark - Binding

// From mach-o/loader.h:
// Dyld binds an image during the loading process, if the image requires any pointers to be initialized to symbols in other images.
// Conceptually the bind information is a table of tuples:
//    <seg-index, seg-offset, type, symbol-library-ordinal, symbol-name, addend>

- (void)parseBindInfo;
{
    if (debugBindOps) {
        VerboseLog(@"----------------------------------------------------------------------");
        VerboseLog(@"bind_off: %u, bind_size: %u", _dyldInfoCommand.bind_off, _dyldInfoCommand.bind_size);
    }
    const uint8_t *start = (uint8_t *)[self.machOFile.data bytes] + _dyldInfoCommand.bind_off;
    const uint8_t *end = start + _dyldInfoCommand.bind_size;

    [self logBindOps:start end:end isLazy:NO];
}

- (void)parseWeakBindInfo;
{
    if (debugBindOps) {
        VerboseLog(@"----------------------------------------------------------------------");
        VerboseLog(@"weak_bind_off: %u, weak_bind_size: %u", _dyldInfoCommand.weak_bind_off, _dyldInfoCommand.weak_bind_size);
    }
    const uint8_t *start = (uint8_t *)[self.machOFile.data bytes] + _dyldInfoCommand.weak_bind_off;
    const uint8_t *end = start + _dyldInfoCommand.weak_bind_size;

    [self logBindOps:start end:end isLazy:NO];
}

- (void)logLazyBindInfo;
{
    if (debugBindOps) {
        VerboseLog(@"----------------------------------------------------------------------");
        VerboseLog(@"lazy_bind_off: %u, lazy_bind_size: %u", _dyldInfoCommand.lazy_bind_off, _dyldInfoCommand.lazy_bind_size);
    }
    const uint8_t *start = (uint8_t *)[self.machOFile.data bytes] + _dyldInfoCommand.lazy_bind_off;
    const uint8_t *end = start + _dyldInfoCommand.lazy_bind_size;

    [self logBindOps:start end:end isLazy:YES];
}

- (void)logBindOps:(const uint8_t *)start end:(const uint8_t *)end isLazy:(BOOL)isLazy;
{
    BOOL isDone = NO;
    NSUInteger bindCount = 0;
    int64_t libraryOrdinal = 0;
    uint8_t type = 0;
    int64_t addend = 0;
    uint8_t segmentIndex = 0;
    const char *symbolName = NULL;
    uint8_t symbolFlags = 0;

    NSArray *segments = [self.machOFile segments];
    NSParameterAssert([segments count] > 0);

    uint64_t address = [segments[0] vmaddr];

    const uint8_t *ptr = start;
    while ((ptr < end) && isDone == NO) {
        uint8_t immediate = *ptr & BIND_IMMEDIATE_MASK;
        uint8_t opcode = *ptr & BIND_OPCODE_MASK;
        ptr++;

        switch (opcode) {
            case BIND_OPCODE_DONE:
                if (debugBindOps) VerboseLog(@"BIND_OPCODE: DONE");
                
                // The lazy bindings have one of these at the end of each bind.
                if (isLazy == NO)
                    isDone = YES;
                break;
                
            case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
                libraryOrdinal = immediate;
                if (debugBindOps) VerboseLog(@"BIND_OPCODE: SET_DYLIB_ORDINAL_IMM,          libraryOrdinal = %lld", libraryOrdinal);
                break;
                
            case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
                libraryOrdinal = read_uleb128(&ptr, end);
                if (debugBindOps) VerboseLog(@"BIND_OPCODE: SET_DYLIB_ORDINAL_ULEB,         libraryOrdinal = %lld", libraryOrdinal);
                break;
                
            case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM: {
                // Special means negative
                if (immediate == 0)
                    libraryOrdinal = 0;
                else {
                    int8_t val = immediate | BIND_OPCODE_MASK; // This sign extends the value
                    
                    libraryOrdinal = val;
                }
                if (debugBindOps) VerboseLog(@"BIND_OPCODE: SET_DYLIB_SPECIAL_IMM,          libraryOrdinal = %lld", libraryOrdinal);
                break;
            }
                
            case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
                symbolName = (const char *)ptr;
                symbolFlags = immediate;
                if (debugBindOps) VerboseLog(@"BIND_OPCODE: SET_SYMBOL_TRAILING_FLAGS_IMM,  flags: %02x, str = %s", symbolFlags, symbolName);
                while (*ptr != 0)
                    ptr++;
                
                ptr++; // skip the trailing zero
                
                break;
                
            case BIND_OPCODE_SET_TYPE_IMM:
                if (debugBindOps) VerboseLog(@"BIND_OPCODE: SET_TYPE_IMM,                   type = %u (%@)", immediate, CDBindTypeDescription(immediate));
                type = immediate;
                break;
                
            case BIND_OPCODE_SET_ADDEND_SLEB:
                addend = read_sleb128(&ptr, end);
                if (debugBindOps) VerboseLog(@"BIND_OPCODE: SET_ADDEND_SLEB,                addend = %lld", addend);
                break;
                
            case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: {
                segmentIndex = immediate;
                uint64_t val = read_uleb128(&ptr, end);
                if (debugBindOps) VerboseLog(@"BIND_OPCODE: SET_SEGMENT_AND_OFFSET_ULEB,    segmentIndex: %u, offset: 0x%016llx", segmentIndex, val);
                address = [segments[segmentIndex] vmaddr] + val;
                if (debugBindOps) VerboseLog(@"    address = 0x%016llx", address);
                break;
            }
                
            case BIND_OPCODE_ADD_ADDR_ULEB: {
                uint64_t val = read_uleb128(&ptr, end);
                if (debugBindOps) VerboseLog(@"BIND_OPCODE: ADD_ADDR_ULEB,                  addr += 0x%016llx", val);
                address += val;
                break;
            }
                
            case BIND_OPCODE_DO_BIND:
                if (debugBindOps) VerboseLog(@"BIND_OPCODE: DO_BIND");
                [self bindAddress:address type:type symbolName:symbolName flags:symbolFlags addend:addend libraryOrdinal:libraryOrdinal];
                address += _ptrSize;
                bindCount++;
                break;
                
            case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB: {
                uint64_t val = read_uleb128(&ptr, end);
                if (debugBindOps) VerboseLog(@"BIND_OPCODE: DO_BIND_ADD_ADDR_ULEB,          address += %016llx", val);
                [self bindAddress:address type:type symbolName:symbolName flags:symbolFlags addend:addend libraryOrdinal:libraryOrdinal];
                address += _ptrSize + val;
                bindCount++;
                break;
            }
                
            case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
                if (debugBindOps) VerboseLog(@"BIND_OPCODE: DO_BIND_ADD_ADDR_IMM_SCALED,    address += %u * %lu", immediate, _ptrSize);
                [self bindAddress:address type:type symbolName:symbolName flags:symbolFlags addend:addend libraryOrdinal:libraryOrdinal];
                address += _ptrSize + immediate * _ptrSize;
                bindCount++;
                break;
                
            case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB: {
                uint64_t count = read_uleb128(&ptr, end);
                uint64_t skip = read_uleb128(&ptr, end);
                if (debugBindOps) VerboseLog(@"BIND_OPCODE: DO_BIND_ULEB_TIMES_SKIPPING_ULEB, count: %016llx, skip: %016llx", count, skip);
                for (uint64_t index = 0; index < count; index++) {
                    [self bindAddress:address type:type symbolName:symbolName flags:symbolFlags addend:addend libraryOrdinal:libraryOrdinal];
                    address += _ptrSize + skip;
                }
                bindCount += count;
                break;
            }
                
            default:
                VerboseLog(@"Unknown opcode op: %x, imm: %x", opcode, immediate);
                exit(99);
        }
    }

    if (debugBindOps) {
        VerboseLog(@"    ptr: %p, end: %p, bytes left over: %ld", ptr, end, end - ptr);
        VerboseLog(@"    bindCount: %lu", bindCount);
        VerboseLog(@"----------------------------------------------------------------------");
    }
}

- (void)bindAddress:(uint64_t)address type:(uint8_t)type symbolName:(const char *)symbolName flags:(uint8_t)flags
             addend:(int64_t)addend libraryOrdinal:(int64_t)libraryOrdinal;
{
#if 0
    VerboseLog(@"    Bind address: %016lx, type: 0x%02x, flags: %02x, addend: %016lx, libraryOrdinal: %ld, symbolName: %s",
          address, type, flags, addend, libraryOrdinal, symbolName);
#endif

    NSNumber *key = [NSNumber numberWithUnsignedInteger:address]; // I don't think 32-bit will dump 64-bit stuff.
    NSString *str = [[NSString alloc] initWithUTF8String:symbolName];
    _symbolNamesByAddress[key] = str;
}

#pragma mark - Exported symbols

- (void)logExportedSymbols;
{
    VLOG_CMD;
    if (debugExportedSymbols) {
        VerboseLog(@"----------------------------------------------------------------------");
        VerboseLog(@"export_off: %u, export_size: %u", _dyldInfoCommand.export_off, _dyldInfoCommand.export_size);
        VerboseLog(@"hexdump -Cv -s %u -n %u", _dyldInfoCommand.export_off, _dyldInfoCommand.export_size);
    }

    const uint8_t *start = (uint8_t *)[self.machOFile.data bytes] + _dyldInfoCommand.export_off;
    const uint8_t *end = start + _dyldInfoCommand.export_size;

    VerboseLog(@"         Type Flags Offset           Name");
    VerboseLog(@"------------- ----- ---------------- ----");
    [self printSymbols:start end:end prefix:@"" offset:0];
}

- (void)printSymbols:(const uint8_t *)start end:(const uint8_t *)end prefix:(NSString *)prefix offset:(uint64_t)offset;
{
    //VerboseLog(@" > %s, %p-%p, offset: %lx = %p", _cmds, start, end, offset, start + offset);

    const uint8_t *ptr = start + offset;
    if (ptr < end) {
        VerboseLog(@"ptv < end, stop printing symbols");
        return;
    }
    //NSParameterAssert(ptr < end);

    uint8_t terminalSize = *ptr++;
    const uint8_t *tptr = ptr;
    //VerboseLog(@"terminalSize: %u", terminalSize);

    ptr += terminalSize;

    uint8_t childCount = *ptr++;

    if (terminalSize > 0) {
        //VerboseLog(@"symbol: '%@', terminalSize: %u", prefix, terminalSize);
        uint64_t flags = read_uleb128(&tptr, end);
        uint8_t kind = flags & EXPORT_SYMBOL_FLAGS_KIND_MASK;
        if (kind == EXPORT_SYMBOL_FLAGS_KIND_REGULAR) {
            uint64_t symbolOffset = read_uleb128(&tptr, end);
            VerboseLog(@"     Regular: %04llx  %016llx %@", flags, symbolOffset, prefix);
            //VerboseLog(@"     Regular: %04x  0x%08x %@", flags, symbolOffset, prefix);
        } else if (kind == EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL) {
            VerboseLog(@"Thread Local: %04llx                   %@, terminalSize: %u", flags, prefix, terminalSize);
        } else {
            VerboseLog(@"     Unknown: %04llx  %x, name: %@, terminalSize: %u", flags, kind, prefix, terminalSize);
        }
    }

    for (uint8_t index = 0; index < childCount; index++) {
        const uint8_t *edgeStart = ptr;

        while (*ptr++ != 0)
            ;

        //NSUInteger length = ptr - edgeStart;
        //VerboseLog(@"edge length: %u, edge: '%s'", length, edgeStart);
        uint64_t nodeOffset = read_uleb128(&ptr, end);
        //VerboseLog(@"node offset: %lx", nodeOffset);

        [self printSymbols:start end:end prefix:[NSString stringWithFormat:@"%@%s", prefix, edgeStart] offset:nodeOffset];
    }

    //VerboseLog(@"<  %s, %p-%p, offset: %lx = %p", _cmds, start, end, offset, start + offset);
}

@end
