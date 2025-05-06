//
//  CDLCExportTRIEData.h
//  classdumpios
//
//  Created by kevinbradley on 6/26/22.
//

//#import <classdump/classdump.h>
#import "CDLoadCommand.h"
NS_ASSUME_NONNULL_BEGIN

@interface CDLCExportTRIEData : CDLoadCommand
- (uint64_t)getExportedSymbolLocation:(NSString *)symbol;
@end

NS_ASSUME_NONNULL_END
