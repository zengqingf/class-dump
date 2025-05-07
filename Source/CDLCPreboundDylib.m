// -*- mode: ObjC -*-

//  This file is part of class-dump, a utility for examining the Objective-C segment of Mach-O files.
//  Copyright (C) 1997-2019 Steve Nygard.

#import "CDLCPreboundDylib.h"

#import "CDFatFile.h"
#import "CDMachOFile.h"

@implementation CDLCPreboundDylib
{
    struct prebound_dylib_command _preboundDylibCommand;
}

- (id)initWithDataCursor:(CDMachOFileDataCursor *)cursor;
{
    if ((self = [super initWithDataCursor:cursor])) {
        //DLog(@"current offset: %u", [cursor offset]);
        _preboundDylibCommand.cmd     = [cursor readInt32];
        _preboundDylibCommand.cmdsize = [cursor readInt32];
        //DLog(@"cmdsize: %u", preboundDylibCommand.cmdsize);
        
        _preboundDylibCommand.name.offset           = [cursor readInt32];
        _preboundDylibCommand.nmodules              = [cursor readInt32];
        _preboundDylibCommand.linked_modules.offset = [cursor readInt32];
        
        if (_preboundDylibCommand.cmdsize > 20) {
            // Don't need this info right now.
            @try {
                [cursor advanceByLength:_preboundDylibCommand.cmdsize - 20];
            } @catch (NSException *exception) {
                CAUGHT_EXCEPTION_LOG;
            }
        }
    }

    return self;
}

#pragma mark -

- (uint32_t)cmd;
{
    return _preboundDylibCommand.cmd;
}

- (uint32_t)cmdsize;
{
    return _preboundDylibCommand.cmdsize;
}

@end
