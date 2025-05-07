// -*- mode: ObjC -*-

//  This file is part of class-dump, a utility for examining the Objective-C segment of Mach-O files.
//  Copyright (C) 1997-2019 Steve Nygard.

#import "CDLCUnknown.h"

@implementation CDLCUnknown
{
    struct load_command _loadCommand;
    
    NSData *_commandData;
}

- (id)initWithDataCursor:(CDMachOFileDataCursor *)cursor;
{
    if ((self = [super initWithDataCursor:cursor])) {
        VerboseLog(@"offset: %lu", [cursor offset]);
        _loadCommand.cmd     = [cursor readInt32];
        _loadCommand.cmdsize = [cursor readInt32];
         VerboseLog(@"cmdsize: %u", _loadCommand.cmdsize);
        
        if (_loadCommand.cmdsize > 8) {
            NSMutableData *commandData = [[NSMutableData alloc] init];
            @try {
                [cursor appendBytesOfLength:_loadCommand.cmdsize - 8 intoData:commandData];
                _commandData = [commandData copy];
            } @catch (NSException *exception) {
                CAUGHT_EXCEPTION_LOG;
                commandData = nil;
            }
            
        } else {
            _commandData = nil;
        }
    }

    return self;
}

#pragma mark -

- (uint32_t)cmd;
{
    return _loadCommand.cmd;
}

- (uint32_t)cmdsize;
{
    return _loadCommand.cmdsize;
}

@end
