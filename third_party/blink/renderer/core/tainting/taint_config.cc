#include "third_party/blink/renderer/core/tainting/taint_config.h"

#include <array>
#include <iterator>
#include <string>
#include <string_view>

#include "base/feature_list.h"
#include "third_party/blink/renderer/platform/wtf/hash_map.h"
#include "third_party/blink/renderer/platform/wtf/std_lib_extras.h"
#include "third_party/blink/renderer/platform/wtf/text/string_hash.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

BASE_FEATURE(kTaintTrackingActive, "TaintTracking", base::FEATURE_ENABLED_BY_DEFAULT);

namespace {

constexpr std::string_view kTaintPrefNames[] = {
    "source.location.hash",
    "source.location.host",
    "source.location.hostname",
    "source.location.href",
    "source.location.origin",
    "source.location.pathname",
    "source.location.port",
    "source.location.protocol",
    "source.location.search",
    "source.window.name",
    "source.document.referrer",
    "source.document.baseURI",
    "source.document.documentURI",
    "source.document.cookie",
    "source.localStorage.getItem",
    "source.sessionStorage.getItem",
    "source.MessageEvent",
    "source.PushMessageData",
    "source.PushSubscription.endpoint",
    "source.WebSocket.MessageEvent.data",
    "source.XMLHttpRequest.response",
    "source.input.value",
    "source.textarea.value",
    "source.script.innerHTML",
    "source.document.getElementById",
    "source.document.getElementsByTagName",
    "source.document.getElementsByTagNameNS",
    "source.document.getElementsByClassName",
    "source.document.querySelector",
    "source.document.querySelectorAll",
    "source.document.elementFromPoint",
    "source.document.elementsFromPoint",
    "source.element.attribute",
    "source.element.closest",
    "sink.element.after",
    "sink.element.before",
    "sink.EventSource",
    "sink.Function.ctor",
    "sink.Range.createContextualFragment(fragment)",
    "sink.WebSocket",
    "sink.WebSocket.send",
    "sink.XMLHttpRequest.open(password)",
    "sink.XMLHttpRequest.open(url)",
    "sink.XMLHttpRequest.open(username)",
    "sink.XMLHttpRequest.send",
    "sink.XMLHttpRequest.setRequestHeader(name)",
    "sink.XMLHttpRequest.setRequestHeader(value)",
    "sink.a.href",
    "sink.area.href",
    "sink.document.cookie",
    "sink.document.writeln",
    "sink.document.write",
    "sink.element.style",
    "sink.embed.src",
    "sink.eval",
    "sink.eventHandler",
    "sink.fetch.body",
    "sink.fetch.url",
    "sink.form.action",
    "sink.iframe.src",
    "sink.iframe.srcdoc",
    "sink.img.src",
    "sink.img.srcset",
    "sink.innerHTML",
    "sink.insertAdjacentHTML",
    "sink.insertAdjacentText",
    "sink.localStorage.setItem",
    "sink.localStorage.setItem(key)",
    "sink.location.assign",
    "sink.location.hash",
    "sink.location.host",
    "sink.location.href",
    "sink.location.pathname",
    "sink.location.port",
    "sink.location.protocol",
    "sink.location.replace",
    "sink.location.search",
    "sink.media.src",
    "sink.navigator.sendBeacon(body)",
    "sink.navigator.sendBeacon(url)",
    "sink.object.data",
    "sink.outerHTML",
    "sink.script.innerHTML",
    "sink.script.src",
    "sink.script.text",
    "sink.script.textContent",
    "sink.sessionStorage.setItem",
    "sink.sessionStorage.setItem(key)",
    "sink.setInterval",
    "sink.setTimeout",
    "sink.source",
    "sink.srcset",
    "sink.track.src",
    "sink.window.open",
    "sink.window.postMessage",
};

using TaintOverrideMap = HashMap<String, bool>;

TaintOverrideMap& Overrides() {
  DEFINE_STATIC_LOCAL(TaintOverrideMap, map, ());
  return map;
}

}  // namespace

bool TaintIsActive(const char* name) {
  if (!base::FeatureList::IsEnabled(kTaintTrackingActive)) {
    return false;
  }
  const auto it = Overrides().find(String(name));
  return it == Overrides().end() ? true : it->value;
}

void TaintSetActive(const char* name, bool enabled) {
  Overrides().Set(String(name), enabled);
}

size_t TaintPrefCount() {
  return std::size(kTaintPrefNames);
}

bool TaintIsSourceActive(const char* name) {
  std::string full = "source.";
  full += name;
  return TaintIsActive(full.c_str());
}

bool TaintIsSinkActive(const char* name) {
  std::string full = "sink.";
  full += name;
  return TaintIsActive(full.c_str());
}

}  // namespace blink
