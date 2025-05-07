// -*- mode: ObjC -*-

//  This file is part of class-dump, a utility for examining the Objective-C segment of Mach-O files.
//  Copyright (C) 1997-2019 Steve Nygard.

#import "CDLCDylinker.h"

@implementation CDLCDylinker
{
    struct dylinker_command _dylinkerCommand;
    NSString *_name;
}

- (id)initWithDataCursor:(CDMachOFileDataCursor *)cursor;
{
    if ((self = [super initWithDataCursor:cursor])) {
        _dylinkerCommand.cmd     = [cursor readInt32];
        _dylinkerCommand.cmdsize = [cursor readInt32];

        _dylinkerCommand.name.offset = [cursor readInt32];
        
        NSUInteger length = _dylinkerCommand.cmdsize - sizeof(_dylinkerCommand);
        //DLog(@"expected length: %u", length);
        @try {
            _name = [cursor readStringOfLength:length encoding:NSASCIIStringEncoding];
        } @catch (NSException *exception) {
            CAUGHT_EXCEPTION_LOG;
            _name = nil;
        }
        //DLog(@"name: %@", name);
    }

    return self;
}

#pragma mark -

- (uint32_t)cmd;
{
    return _dylinkerCommand.cmd;
}

- (uint32_t)cmdsize;
{
    return _dylinkerCommand.cmdsize;
}

@end
