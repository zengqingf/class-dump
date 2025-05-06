//
//  CDLCExportTRIEData.m
//  classdumpios
//
//  Created by kevinbradley on 6/26/22.
//

#import "CDLCExportTRIEData.h"
#import "CDMachOFile.h"

#import "CDLCSegment.h"
#import "ULEB128.h"

#ifdef DEBUG
//static BOOL debugBindOps = YES;
static BOOL debugExportedSymbols = YES;
#else
//static BOOL debugBindOps = NO;
static BOOL debugExportedSymbols = NO;
#endif


@implementation CDLCExportTRIEData
{
    struct linkedit_data_command _linkeditDataCommand;
    NSData *_linkeditData;
    NSMutableDictionary *_symbolData;
}

- (id)initWithDataCursor:(CDMachOFileDataCursor *)cursor;
{
    if ((self = [super initWithDataCursor:cursor])) {
        _linkeditDataCommand.cmd     = [cursor readInt32];
        _linkeditDataCommand.cmdsize = [cursor readInt32];
        
        _linkeditDataCommand.dataoff  = [cursor readInt32];
        _linkeditDataCommand.datasize = [cursor readInt32];
        _symbolData = [NSMutableDictionary new];
    }

    return self;
}

#pragma mark -

- (uint32_t)cmd;
{
    return _linkeditDataCommand.cmd;
}

- (uint32_t)cmdsize;
{
    return _linkeditDataCommand.cmdsize;
}

- (NSData *)linkeditData;
{
    if (_linkeditData == NULL) {
        _linkeditData = [[NSData alloc] initWithBytes:[self.machOFile bytesAtOffset:_linkeditDataCommand.dataoff] length:_linkeditDataCommand.datasize];
    }
    
    return _linkeditData;
}

- (void)machOFileDidReadLoadCommands:(CDMachOFile *)machOFile;
{
    if ([CDClassDump isVerbose]){
        [self logExportedSymbols];
        InfoLog(@"_symbolData: %@", _symbolData);
    }
    
}

- (void)logExportedSymbols;
{
    if (debugExportedSymbols) {
        InfoLog(@"----------------------------------------------------------------------");
        InfoLog(@"export_off: %u, export_size: %u", _linkeditDataCommand.dataoff, _linkeditDataCommand.datasize);
        InfoLog(@"hexdump -Cv -s %u -n %u", _linkeditDataCommand.dataoff, _linkeditDataCommand.datasize);
    }

    const uint8_t *start = (uint8_t *)[self.machOFile.data bytes] + _linkeditDataCommand.dataoff;
    const uint8_t *end = start + _linkeditDataCommand.datasize;

    InfoLog(@"         Type Flags Offset           Name");
    InfoLog(@"------------- ----- ---------------- ----");
    [self printSymbols:start end:end prefix:@"" offset:0];
}

- (void)printSymbols:(const uint8_t *)start end:(const uint8_t *)end prefix:(NSString *)prefix offset:(uint64_t)offset;
{
    VerboseLog(@" > %s, %p-%p, offset: %lx = %p", _cmds, start, end, offset, start + offset);

    const uint8_t *ptr = start + offset;
    if (ptr < end) {
        VerboseLog(@"ptv < end, stop printing symbols");
        return;
    }
    //NSParameterAssert(ptr < end);

    uint8_t terminalSize = *ptr++;
    const uint8_t *tptr = ptr;
    VerboseLog(@"terminalSize: %u", terminalSize);

    ptr += terminalSize;

    uint8_t childCount = *ptr++;

    if (terminalSize > 0) {
        //VerboseLog(@"symbol: '%@', terminalSize: %u", prefix, terminalSize);
        uint64_t flags = read_uleb128(&tptr, end);
        uint8_t kind = flags & EXPORT_SYMBOL_FLAGS_KIND_MASK;
        if (kind == EXPORT_SYMBOL_FLAGS_KIND_REGULAR) {
            uint64_t symbolOffset = read_uleb128(&tptr, end);
            InfoLog(@"     Regular: %04llx  %016llx %@", flags, symbolOffset, prefix);
            //VerboseLog(@"     Regular: %04x  0x%08x %@", flags, symbolOffset, prefix);
            NSDictionary *_symbol = @{@"type": @"Regular",
                                      @"flags": [NSNumber numberWithUnsignedInteger:flags],
                                      @"symbolOffset": [NSNumber numberWithUnsignedInteger:symbolOffset],
                                      @"symbol": prefix};
            _symbolData[prefix] = _symbol;
        } else if (kind == EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL) {
            InfoLog(@"Thread Local: %04llx                   %@, terminalSize: %u", flags, prefix, terminalSize);
        } else {
            InfoLog(@"     Unknown: %04llx  %x, name: %@, terminalSize: %u", flags, kind, prefix, terminalSize);
        }
    }

    for (uint8_t index = 0; index < childCount; index++) {
        const uint8_t *edgeStart = ptr;

        while (*ptr++ != 0)
            ;

        NSUInteger length = ptr - edgeStart;
        VerboseLog(@"edge length: %u, edge: '%s'", length, edgeStart);
        uint64_t nodeOffset = read_uleb128(&ptr, end);
        VerboseLog(@"node offset: %lx", nodeOffset);

        [self printSymbols:start end:end prefix:[NSString stringWithFormat:@"%@%s", prefix, edgeStart] offset:nodeOffset];
    }

    VerboseLog(@"<  %s, %p-%p, offset: %lx = %p", _cmds, start, end, offset, start + offset);
}

- (uint64_t)getExportedSymbolLocation:(NSString *)symbol {
    return [_symbolData[symbol][@"symbolOffset"] unsignedIntegerValue];
}

@end
