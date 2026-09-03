#ifndef THIRD_PARTY_BLINK_RENDERER_CORE_TAINTING_TAINT_REPORT_H_
#define THIRD_PARTY_BLINK_RENDERER_CORE_TAINTING_TAINT_REPORT_H_

#include "base/functional/callback.h"
#include "taint/Taint.h"
#include "third_party/blink/renderer/core/core_export.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

struct CORE_EXPORT TaintReport {
  String sink_name;
  String value;
  StringTaint taint;
  String location;
};

using TaintReportCallback = base::RepeatingCallback<void(const TaintReport&)>;

CORE_EXPORT void SetTaintExportCallback(TaintReportCallback callback);

CORE_EXPORT void ReportTaintFlow(const char* sink_name,
                                 const String& value,
                                 const StringTaint& taint);

}  // namespace blink

#endif  // THIRD_PARTY_BLINK_RENDERER_CORE_TAINTING_TAINT_REPORT_H_
