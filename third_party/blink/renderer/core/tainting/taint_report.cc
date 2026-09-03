#include "third_party/blink/renderer/core/tainting/taint_report.h"

#include <utility>

#include "third_party/blink/renderer/core/tainting/taint_util.h"
#include "third_party/blink/renderer/platform/wtf/std_lib_extras.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

namespace blink {

namespace {

TaintReportCallback& ExportCallback() {
  DEFINE_STATIC_LOCAL(TaintReportCallback, callback, ());
  return callback;
}

String LocationToString(const TaintLocation& location) {
  const std::u16string& filename = location.filename();
  StringBuilder builder;
  builder.Append(String(base::span(
      reinterpret_cast<const UChar*>(filename.data()), filename.size())));
  builder.Append(':');
  builder.AppendNumber(location.line());
  builder.Append(':');
  builder.AppendNumber(location.pos());
  return builder.ToString();
}

}  // namespace

void SetTaintExportCallback(TaintReportCallback callback) {
  ExportCallback() = std::move(callback);
}

void ReportTaintFlow(const char* sink_name,
                     const String& value,
                     const StringTaint& taint) {
  if (!taint.hasTaint()) {
    return;
  }
  DispatchTaintReportEvent(sink_name, value, taint);
  if (ExportCallback().is_null()) {
    return;
  }
  TaintReport report;
  report.sink_name = String(sink_name);
  report.value = value;
  report.taint = taint;
  report.location = LocationToString(GetTaintLocation());
  ExportCallback().Run(report);
}

}  // namespace blink
