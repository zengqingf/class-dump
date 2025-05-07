// -*- mode: ObjC -*-

//  This file is part of class-dump, a utility for examining the Objective-C segment of Mach-O files.
//  Copyright (C) 1997-2019 Steve Nygard.

#import "CDBalanceFormatter.h"

@implementation CDBalanceFormatter
{
    NSScanner *_scanner;
    NSCharacterSet *_openCloseSet;
    
    NSMutableString *_result;
}

- (id)initWithString:(NSString *)str;
{
    if ((self = [super init])) {
        if (!str){
            VerboseLog(@"%s NSScanner initWithString: %@", _cmds, str);
        }
        _scanner = [[NSScanner alloc] initWithString:str];
        _openCloseSet = [NSCharacterSet characterSetWithCharactersInString:@"{}<>()"];
        
        _result = [[NSMutableString alloc] init];
    }

    return self;
}

#pragma mark -

- (void)parse:(NSString *)open index:(NSUInteger)openIndex level:(NSUInteger)level;
{
    NSString *opens[] = { @"{", @"<", @"(", nil};
    NSString *closes[] = { @"}", @">", @")", nil};
    BOOL foundOpen = NO;
    BOOL foundClose = NO;

    while ([_scanner isAtEnd] == NO) {
        NSString *pre;

        if ([_scanner scanUpToCharactersFromSet:_openCloseSet intoString:&pre]) {
             VerboseLog(@"pre = '%@'", pre);
            [_result appendFormat:@"%@%@\n", [NSString spacesIndentedToLevel:level], pre];
        }
         VerboseLog(@"remaining: '%@'", [[_scanner string] substringFromIndex:[_scanner scanLocation]]);

        foundOpen = foundClose = NO;
        for (NSUInteger index = 0; index < 3; index++) {
             VerboseLog(@"Checking open %lu: '%@'", index, opens[index]);
            if ([_scanner scanString:opens[index] intoString:NULL]) {
                 VerboseLog(@"Start %@", opens[index]);
                [_result appendSpacesIndentedToLevel:level];
                [_result appendString:opens[index]];
                [_result appendString:@"\n"];

                [self parse:opens[index] index:[_scanner scanLocation] - 1 level:level + 1];

                [_result appendSpacesIndentedToLevel:level];
                [_result appendString:closes[index]];
                [_result appendString:@"\n"];
                foundOpen = YES;
                break;
            }

             VerboseLog(@"Checking close %lu: '%@'", index, closes[index]);
            if ([_scanner scanString:closes[index] intoString:NULL]) {
                if ([open isEqualToString:opens[index]]) {
                     VerboseLog(@"End %@", closes[index]);
                } else {
                    VerboseLog(@"ERROR: Unmatched end %@", closes[index]);
                }
                foundClose = YES;
                break;
            }
        }

        if (foundOpen == NO && foundClose == NO) {
             VerboseLog(@"Unknown @ %lu: %@", [_scanner scanLocation], [[_scanner string] substringFromIndex:[_scanner scanLocation]]);
            break;
        }

        if (foundClose)
            break;
    }
}

- (NSString *)format;
{
    [self parse:nil index:0 level:0];

     VerboseLog(@"result:\n%@", _result);

    return [NSString stringWithString:_result];
}

@end
