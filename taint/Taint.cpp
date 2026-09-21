#include "Taint.h"

#include <locale>
#include <codecvt>
#include <stack>
#include <string>
#include <algorithm>
#include <sstream>

#include "json.hpp"

#ifndef MOZ_COUNT_CTOR
#  define MOZ_COUNT_CTOR(X)
#endif

#ifndef MOZ_COUNT_DTOR
#  define MOZ_COUNT_DTOR(X)
#endif

TaintLocation::TaintLocation(std::u16string filename, uint32_t line,
                             uint32_t pos, uint32_t next_line,
                             uint32_t next_pos, uint32_t scriptStartLine,
                             TaintMd5 scriptHash, std::u16string function)
    : filename_(std::move(filename)),
      line_(line),
      pos_(pos),
      next_line_(next_line),
      next_pos_(next_pos),
      scriptStartLine_(scriptStartLine),
      scriptHash_(scriptHash),
      function_(std::move(function)) {}

TaintLocation::TaintLocation()
    : filename_(),
      line_(0),
      pos_(0),
      next_line_(0),
      next_pos_(0),
      scriptStartLine_(0),
      scriptHash_({0}),
      function_() {}

TaintLocation::TaintLocation(TaintLocation&& other) noexcept
    : filename_(std::move(other.filename_)),
      line_(other.line_),
      pos_(other.pos_),
      next_line_(other.next_line_),
      next_pos_(other.next_pos_),
      scriptStartLine_(other.scriptStartLine_),
      scriptHash_(other.scriptHash_),
      function_(std::move(other.function_)) {}

TaintLocation& TaintLocation::operator=(TaintLocation&& other) noexcept {
  filename_ = std::move(other.filename_);
  line_ = other.line_;
  pos_ = other.pos_;
  next_line_ = other.next_line_;
  next_pos_ = other.next_pos_;
  scriptStartLine_ = other.scriptStartLine_;
  scriptHash_ = other.scriptHash_;
  function_ = std::move(other.function_);
  return *this;
}

TaintOperation::TaintOperation(const char* name, TaintLocation location,
                               std::initializer_list<std::u16string> args)
    : name_(name),
      arguments_(args),
      source_(false),
      location_(std::move(location)) {}

TaintOperation::TaintOperation(const char* name, TaintLocation location,
                               std::vector<std::u16string> args)
    : name_(name),
      arguments_(std::move(args)),
      source_(false),
      location_(std::move(location)) {}

TaintOperation::TaintOperation(const char* name,
                               std::initializer_list<std::u16string> args)
    : name_(name), arguments_(args), source_(false) {}

TaintOperation::TaintOperation(const char* name,
                               std::vector<std::u16string> args)
    : name_(name),
      arguments_(std::move(args)),
      source_(false) {}

TaintOperation::TaintOperation(const char* name)
    : name_(name), source_(false) {}

TaintOperation::TaintOperation(const char* name, TaintLocation location)
    : name_(name),
      source_(false),
      location_(std::move(location)) {}

TaintOperation::TaintOperation(TaintOperation&& other) noexcept
    : name_(std::move(other.name_)),
      arguments_(std::move(other.arguments_)),
      source_(other.source_),
      location_(std::move(other.location_)) {}

TaintOperation& TaintOperation::operator=(TaintOperation&& other) noexcept {
  name_ = std::move(other.name_);
  arguments_ = std::move(other.arguments_);
  source_ = other.source_;
  location_ = std::move(other.location_);
  return *this;
}

TaintNode::TaintNode(TaintNode* parent, const TaintOperation& operation)
    : parent_(parent), refcount_(1), operation_(operation) {
  MOZ_COUNT_CTOR(TaintNode);
  if (parent_) {
    parent_->addref();
  }
}

TaintNode::TaintNode(TaintNode* parent, TaintOperation&& operation) noexcept
    : parent_(parent), refcount_(1), operation_(std::move(operation)) {
  MOZ_COUNT_CTOR(TaintNode);
  if (parent_) {
    parent_->addref();
  }
}

TaintNode::TaintNode(const TaintOperation& operation)
    : parent_(nullptr), refcount_(1), operation_(operation) {
  MOZ_COUNT_CTOR(TaintNode);
}

TaintNode::TaintNode(TaintOperation&& operation) noexcept
    : parent_(nullptr), refcount_(1), operation_(std::move(operation)) {
  MOZ_COUNT_CTOR(TaintNode);
}

void TaintNode::addref() {
  if (refcount_ == 0xffffffff) {
    MOZ_CRASH("TaintNode refcount overflow");
  }

  ++refcount_;
}

void TaintNode::release() {
  MOZ_ASSERT(refcount_ > 0);

  --refcount_;
  if (refcount_ == 0) {
    delete this;
  }
}

TaintNode::~TaintNode() {
  MOZ_COUNT_DTOR(TaintNode);
  if (parent_) {
    parent_->release();
  }
}

TaintFlow::Iterator::Iterator(TaintNode* head) : current_(head) {}

TaintFlow::Iterator::Iterator() : current_(nullptr) {}

TaintFlow::Iterator::Iterator(const Iterator& other)
    : current_(other.current_) {}

TaintFlow::Iterator& TaintFlow::Iterator::operator++() {
  current_ = current_->parent();
  return *this;
}

TaintNode& TaintFlow::Iterator::operator*() const { return *current_; }

bool TaintFlow::Iterator::operator==(const Iterator& other) const {
  return current_ == other.current_;
}

bool TaintFlow::Iterator::operator!=(const Iterator& other) const {
  return current_ != other.current_;
}

TaintFlow::TaintFlow() : head_(nullptr) { MOZ_COUNT_CTOR(TaintFlow); }

TaintFlow::TaintFlow(TaintNode* head) : head_(head) {
  MOZ_COUNT_CTOR(TaintFlow);
}

TaintFlow::TaintFlow(const TaintOperation& source)
    : head_(new TaintNode(source)) {
  MOZ_COUNT_CTOR(TaintFlow);
}

TaintFlow::TaintFlow(const TaintFlow& other) : head_(other.head_) {
  MOZ_COUNT_CTOR(TaintFlow);
  if (head_) {
    head_->addref();
  }
}

TaintFlow::TaintFlow(const TaintFlow* other) : head_(nullptr) {
  MOZ_COUNT_CTOR(TaintFlow);
  if (other) {
    head_ = other->head_;
    if (head_) {
      head_->addref();
    }
  }
}

TaintFlow::TaintFlow(TaintFlow&& other) noexcept : head_(other.head_) {
  MOZ_COUNT_CTOR(TaintFlow);
  other.head_ = nullptr;
}

TaintFlow::~TaintFlow() {
  MOZ_COUNT_DTOR(TaintFlow);
  if (head_) {
    head_->release();
  }
}

TaintFlow& TaintFlow::operator=(const TaintFlow& other) {
  if (this == &other) {
    return *this;
  }
  if (head_) {
    head_->release();
  }

  head_ = other.head_;
  if (head_) {
    head_->addref();
  }

  return *this;
}

[[clang::no_destroy]] TaintFlow TaintFlow::empty_flow_ = TaintFlow();

const TaintFlow& TaintFlow::getEmptyTaintFlow() {
  return TaintFlow::empty_flow_;
}

const TaintOperation& TaintFlow::source() const {
  TaintNode* source = head_;
  while (source->parent() != nullptr) {
    source = source->parent();
  }

  return source->operation();
}

TaintFlow& TaintFlow::extend(const TaintOperation& operation) {
  TaintNode* newhead = new TaintNode(head_, operation);
  if (head_) {
    head_->release();
  }
  head_ = newhead;
  return *this;
}

TaintFlow& TaintFlow::extend(const TaintOperation& operation) const {
  TaintFlow flow(*this);
  return flow.extend(operation);
}

TaintFlow& TaintFlow::extend(TaintOperation&& operation) {
  TaintNode* newhead = new TaintNode(head_, std::move(operation));
  if (head_) {
    head_->release();
  }
  head_ = newhead;
  return *this;
}

TaintFlow::Iterator TaintFlow::begin() const { return Iterator(head_); }

TaintFlow::Iterator TaintFlow::end() const { return Iterator(); }

TaintFlow TaintFlow::extend(const TaintFlow& flow,
                            const TaintOperation& operation) {
  return TaintFlow(new TaintNode(flow.head_, operation));
}

TaintFlow TaintFlow::append(const TaintFlow& first, const TaintFlow& second) {
  TaintFlow outFlow(first);
  std::stack<const TaintNode*> q;
  for (const TaintNode& node : second) {
    q.push(&node);
  }
  for (; !q.empty(); q.pop()) {
    const TaintNode* node = q.top();
    outFlow.extend(node->operation());
  }
  return outFlow;
}

TaintRange::TaintRange() : begin_(0), end_(0), flow_() {
  MOZ_COUNT_CTOR(TaintRange);
}

TaintRange::TaintRange(uint32_t begin, uint32_t end, TaintFlow flow)
    : begin_(begin), end_(end), flow_(std::move(flow)) {
  MOZ_COUNT_CTOR(TaintRange);
  MOZ_ASSERT(begin <= end);
}

TaintRange::TaintRange(const TaintRange& other)
    : begin_(other.begin_), end_(other.end_), flow_(other.flow_) {
  MOZ_COUNT_CTOR(TaintRange);
}

TaintRange::~TaintRange() { MOZ_COUNT_DTOR(TaintRange); }

TaintRange& TaintRange::operator=(const TaintRange& other) {
  begin_ = other.begin_;
  end_ = other.end_;
  flow_ = other.flow_;

  return *this;
}

bool TaintRange::operator<(const TaintRange& other) const {
  return this->end() < other.begin();
}

bool TaintRange::operator<(uint32_t index) const { return this->end() < index; }

bool TaintRange::operator>(uint32_t index) const {
  return this->begin() > index;
}

bool TaintRange::operator==(uint32_t index) const {
  return this->contains(index);
}

bool TaintRange::contains(uint32_t index) const {
  return this->begin() <= index && this->end() > index;
}

void TaintRange::resize(uint32_t begin, uint32_t end) {
  MOZ_ASSERT(begin <= end);

  begin_ = begin;
  end_ = end;
}

uint32_t TaintRange::convertBaseBegin(uint32_t ntet, uint32_t nwidth,
                                      uint32_t mwidth) {
  MOZ_ASSERT(ntet >= 0);
  MOZ_ASSERT(nwidth > 0);
  MOZ_ASSERT(mwidth > 0);

  return (ntet * nwidth) / mwidth;
}

uint32_t TaintRange::convertBaseEnd(uint32_t ntet, uint32_t nwidth,
                                    uint32_t mwidth) {
  MOZ_ASSERT(ntet >= 0);
  MOZ_ASSERT(nwidth > 0);
  MOZ_ASSERT(mwidth > 0);

  return (ntet * nwidth + nwidth - 1) / mwidth;
}

void TaintRange::toBase64() {
  resize(convertBaseBegin(begin_, 8, 6), convertBaseEnd(end_, 8, 6));
}

void TaintRange::fromBase64() {
  resize(convertBaseBegin(begin_, 6, 8), convertBaseEnd(end_, 6, 8));
}

#ifdef DEBUG

static void check_ranges(const std::vector<TaintRange>* ranges) {
  uint32_t last_end = 0;

  if (!ranges) {
    return;
  }

  for (auto& range : *ranges) {
    MOZ_ASSERT(range.begin() < range.end());
    MOZ_ASSERT(last_end <= range.begin());
    last_end = range.end();
  }
}

#  define CHECK_RANGES(ranges) check_ranges((ranges))
#else
#  define CHECK_RANGES(ranges)
#endif

StringTaint::StringTaint(const TaintRange& range) {
  MOZ_COUNT_CTOR(StringTaint);
  ranges_ = new std::vector<TaintRange>;
  ranges_->push_back(range);
  CHECK_RANGES(ranges_);
}

StringTaint::StringTaint(uint32_t begin, uint32_t end,
                         const TaintOperation& operation) {
  MOZ_COUNT_CTOR(StringTaint);
  ranges_ = new std::vector<TaintRange>;
  TaintRange range(begin, end, TaintFlow(new TaintNode(operation)));
  ranges_->push_back(range);
  CHECK_RANGES(ranges_);
}

StringTaint::StringTaint(const TaintFlow& flow, uint32_t length)
    : ranges_(nullptr) {

  if (flow) {
    MOZ_COUNT_CTOR(StringTaint);
    ranges_ = new std::vector<TaintRange>;
    ranges_->emplace_back(0, length, flow);
    CHECK_RANGES(ranges_);
  }
}

StringTaint::StringTaint(const StringTaint& other) : ranges_(nullptr) {
  if (other.ranges_) {
    MOZ_COUNT_CTOR(StringTaint);
    ranges_ = new std::vector<TaintRange>(*other.ranges_);
  }
  CHECK_RANGES(ranges_);
}

void StringTaint::assignFromSubTaint(const StringTaint& other, uint32_t begin,
                                     uint32_t end) {
  MOZ_COUNT_CTOR(StringTaint);
  auto* ranges = new std::vector<TaintRange>();
  if (other.ranges_) {

    auto range = std::lower_bound(other.begin(), other.end(), begin);
    for (; range != other.end(); range++) {
      if (range->begin() < end && range->end() > begin && end > begin) {
        ranges->push_back(TaintRange(std::max(range->begin(), begin) - begin,
                                     std::min(range->end(), end) - begin,
                                     range->flow()));
      }

      if (range->end() > end) {
        break;
      }
    }
  }
  assign(ranges);
  CHECK_RANGES(ranges_);
}

StringTaint::StringTaint(const StringTaint& other, uint32_t begin, uint32_t end)
    : ranges_(nullptr) {
  assignFromSubTaint(other, begin, end);
}

StringTaint::StringTaint(const StringTaint& other, uint32_t index)
    : ranges_(nullptr) {
  assignFromSubTaint(other, index, index + 1);
}

StringTaint::StringTaint(StringTaint&& other) noexcept : ranges_(nullptr) {
  ranges_ = other.ranges_;
  other.ranges_ = nullptr;
  CHECK_RANGES(ranges_);
}

StringTaint& StringTaint::operator=(const StringTaint& other) {
  if (this == &other) {
    return *this;
  }

  clear();

  if (other.ranges_) {
    MOZ_COUNT_CTOR(StringTaint);
    ranges_ = new std::vector<TaintRange>(*other.ranges_);
  } else {
    ranges_ = nullptr;
  }
  CHECK_RANGES(ranges_);
  return *this;
}

StringTaint& StringTaint::operator=(StringTaint&& other) noexcept {
  if (this == &other) {
    return *this;
  }

  clear();

  ranges_ = other.ranges_;
  other.ranges_ = nullptr;

  CHECK_RANGES(ranges_);
  return *this;
}

void StringTaint::clear() {
  if (ranges_ != nullptr) {
    ranges_->clear();
    delete ranges_;
    ranges_ = nullptr;
    MOZ_COUNT_DTOR(StringTaint);
  }
}

SafeStringTaint StringTaint::safeCopy() const { return SafeStringTaint(*this); }

SafeStringTaint StringTaint::safeSubTaint(uint32_t begin, uint32_t end) const {

  return SafeStringTaint(*this, begin, end);
}

SafeStringTaint StringTaint::safeSubTaint(uint32_t index) const {

  return SafeStringTaint(*this, index);
}

void StringTaint::clearBetween(uint32_t begin, uint32_t end) {
  MOZ_ASSERT(begin <= end);

  if (begin == end) {
    return;
  }

  MOZ_COUNT_CTOR(StringTaint);
  auto* ranges = new std::vector<TaintRange>();
  for (auto& range : *this) {
    if (range.end() <= begin || range.begin() >= end) {
      ranges->emplace_back(range.begin(), range.end(), range.flow());
    } else {
      if (range.begin() < begin) {
        ranges->emplace_back(range.begin(), begin, range.flow());
      }
      if (range.end() > end) {
        ranges->emplace_back(end, range.end(), range.flow());
      }
    }
  }

  assign(ranges);
}

void StringTaint::shift(uint32_t index, int amount) {
  MOZ_ASSERT(index + amount >= 0);

  if (0 == amount) {
    return;
  }

  MOZ_COUNT_CTOR(StringTaint);
  auto* ranges = new std::vector<TaintRange>();
  for (auto& range : *this) {
    if (range.begin() >= index) {
      ranges->emplace_back(range.begin() + amount, range.end() + amount,
                           range.flow());
    } else if (range.end() > index) {
      MOZ_ASSERT(amount >= 0);
      ranges->emplace_back(range.begin(), index, range.flow());
      ranges->emplace_back(index + amount, range.end() + amount, range.flow());
    } else {
      ranges->emplace_back(range.begin(), range.end(), range.flow());
    }
  }

  assign(ranges);
}

void StringTaint::insert(uint32_t index, const StringTaint& taint) {
  if (!taint.ranges_) {
    return;
  }

  MOZ_COUNT_CTOR(StringTaint);
  auto* ranges = new std::vector<TaintRange>();
  auto it = begin();

  while (it != end() && it->begin() < index) {
    auto& range = *it;
    MOZ_ASSERT(range.end() <= index);
    ranges->emplace_back(range.begin(), range.end(), range.flow());
    it++;
  }

  for (auto& range : taint) {
    ranges->emplace_back(range.begin() + index, range.end() + index,
                         range.flow());
  }

  while (it != end()) {
    auto& range = *it;
    ranges->emplace_back(range.begin(), range.end(), range.flow());
    it++;
  }

  assign(ranges);
}

const TaintFlow* StringTaint::at(uint32_t index) const {
  auto rangeItr = std::lower_bound(begin(), end(), index);
  if (rangeItr != end()) {
    if (rangeItr->contains(index)) {
      return &rangeItr->flow();
    }
  }
  return nullptr;
}

const TaintFlow& StringTaint::atRef(uint32_t index) const {
  auto rangeItr = std::lower_bound(begin(), end(), index);
  if (rangeItr != end()) {
    if (rangeItr->contains(index)) {
      return rangeItr->flow();
    }
  }
  return TaintFlow::getEmptyTaintFlow();
}

void StringTaint::set(uint32_t index, const TaintFlow& flow) {

  if (!ranges_ || index >= ranges_->back().end()) {
    append(TaintRange(index, index + 1, flow));
  } else {
    clearAt(index);
    insert(index, StringTaint(TaintRange(index, index + 1, flow)));
  }
  CHECK_RANGES(ranges_);
}

StringTaint& StringTaint::subtaint(uint32_t begin, uint32_t end) {
  MOZ_ASSERT(begin <= end);
  StringTaint subtaint(*this, begin, end);

  assign(subtaint.ranges_);
  return *this;
}

StringTaint& StringTaint::subtaint(uint32_t index) {
  return subtaint(index, index + 1);
}

StringTaint& StringTaint::extend(const TaintOperation& operation) {
  for (auto& range : *this) {
    range.flow().extend(operation);
  }

  return *this;
}

StringTaint& StringTaint::extend(TaintOperation&& operation) {
  for (auto& range : *this) {
    range.flow().extend(operation);
  }

  return *this;
}

StringTaint& StringTaint::overlay(uint32_t begin, uint32_t end,
                                  const TaintOperation& operation) {
  return overlay(begin, end, TaintFlow(operation));
}

StringTaint& StringTaint::overlay(uint32_t begin, uint32_t end,
                                  const TaintFlow& flow) {
  MOZ_ASSERT(begin <= end);
  CHECK_RANGES(ranges_);

  if (begin == end) {
    return *this;
  }

  if (!flow) {
    return *this;
  }

  if (!ranges_) {
    MOZ_COUNT_CTOR(StringTaint);
    ranges_ = new std::vector<TaintRange>();
    ranges_->emplace_back(begin, end, flow);
    return *this;
  }

  MOZ_COUNT_CTOR(StringTaint);
  auto* ranges = new std::vector<TaintRange>();

  auto current = this->begin();
  auto next = this->begin();

  next++;

  if (begin < current->begin()) {
    ranges->emplace_back(begin, std::min(current->begin(), end), flow);
  }

  while (current != this->end()) {

    MOZ_ASSERT(current->begin() <= current->end());

    if ((end <= current->begin()) || (begin >= current->end())) {
      ranges->emplace_back(current->begin(), current->end(), current->flow());
    } else {

      if (begin > current->begin()) {
        ranges->emplace_back(current->begin(), begin, current->flow());
      }

      if ((current->begin() < end) && (current->end() > begin)) {
        ranges->emplace_back(std::max(current->begin(), begin),
                             std::min(current->end(), end),
                             TaintFlow::append(current->flow(), flow));
      }

      if (end < current->end()) {
        ranges->emplace_back(current->end(), end, current->flow());
      }
    }

    if (next != this->end()) {
      MOZ_ASSERT(next->begin() <= next->end());
      MOZ_ASSERT(next->begin() >= current->end());

      if ((current->end() < end) && (next->begin() > begin) &&
          (next->begin() > current->end())) {
        ranges->emplace_back(std::max(current->end(), begin),
                             std::min(next->begin(), end), flow);
      }
      next++;
    }
    current++;
  }

  if (end > ranges_->back().end()) {
    ranges->emplace_back(std::max(ranges_->back().end(), begin), end, flow);
  }

  assign(ranges);
  return *this;
}

StringTaint& StringTaint::append(TaintRange range) {
  MOZ_ASSERT_IF(ranges_, ranges_->back().end() <= range.begin());

  if (!range.flow()) {
    return *this;
  }

  if (!ranges_) {
    MOZ_COUNT_CTOR(StringTaint);
    ranges_ = new std::vector<TaintRange>;
  }

  if (ranges_->size() > 0) {
    TaintRange& last = ranges_->back();
    if (last.end() == range.begin() && last.flow() == range.flow()) {
      last.resize(last.begin(), range.end());
      return *this;
    }
  }

  ranges_->push_back(range);
  CHECK_RANGES(ranges_);
  return *this;
}

void StringTaint::concat(const StringTaint& other, uint32_t offset) {
  MOZ_ASSERT_IF(ranges_ && ranges_->size() > 0,
                ranges_->back().end() <= offset);

  for (auto& range : other) {
    append(
        TaintRange(range.begin() + offset, range.end() + offset, range.flow()));
  }
}

void StringTaint::concat(const TaintFlow& flow, uint32_t offset) {
  TaintRange range(offset, offset + 1, flow);
  append(range);
}

[[clang::no_destroy]] static std::vector<TaintRange> empty_taint_range_vector;

std::vector<TaintRange>::iterator StringTaint::begin() {

  if (!ranges_) {
    return empty_taint_range_vector.begin();
  }
  return ranges_->begin();
}

std::vector<TaintRange>::iterator StringTaint::end() {
  if (!ranges_) {
    return empty_taint_range_vector.end();
  }
  return ranges_->end();
}

std::vector<TaintRange>::const_iterator StringTaint::begin() const {
  if (!ranges_) {
    return empty_taint_range_vector.begin();
  }
  return ranges_->begin();
}

std::vector<TaintRange>::const_iterator StringTaint::end() const {
  if (!ranges_) {
    return empty_taint_range_vector.end();
  }
  return ranges_->end();
}

void StringTaint::assign(std::vector<TaintRange>* ranges) {
  clear();
  if (ranges && ranges->size() > 0) {
    ranges_ = ranges;
  } else {
    ranges_ = nullptr;

    MOZ_COUNT_DTOR(StringTaint);
    delete ranges;
  }
  CHECK_RANGES(ranges_);
}

void StringTaint::removeOverlaps() {

  if (!ranges_ || ranges_->size() < 2) {
    return;
  }

  auto last = begin();
  auto current = begin();

  current++;

  while (current != end()) {

    MOZ_ASSERT(last->begin() <= last->end());
    MOZ_ASSERT(current->begin() <= current->end());
    MOZ_ASSERT(current->begin() > last->begin());

    if (last->end() > current->begin()) {

      *current = TaintRange(last->end(), current->end(), current->flow());
    }

    if (current->begin() >= current->end()) {
      current = ranges_->erase(current);

    } else {
      last = current;
      current++;
    }
  }
  CHECK_RANGES(ranges_);
}

StringTaint& StringTaint::toBase64() {
  for (auto& range : *this) {
    range.toBase64();
  }
  removeOverlaps();

  return *this;
}

StringTaint& StringTaint::fromBase64() {
  for (auto& range : *this) {
    range.fromBase64();
  }
  removeOverlaps();

  return *this;
}

TaintList& TaintList::append(TaintFlow flow) {

  if (!flow) {
    return *this;
  }

  if (!flows_) {
    MOZ_COUNT_CTOR(TaintList);
    flows_ = new std::vector<TaintFlow>;
  }

  flows_->push_back(flow);
  return *this;
}

void TaintList::clear() {
  if (flows_ != nullptr) {
    flows_->clear();
    MOZ_COUNT_DTOR(TaintList);
    delete flows_;
    flows_ = nullptr;
  }
}

[[clang::no_destroy]] static std::vector<TaintFlow> empty_taint_flow_vector;

std::vector<TaintFlow>::iterator TaintList::begin() {

  if (!flows_) {
    return empty_taint_flow_vector.begin();
  }
  return flows_->begin();
}

std::vector<TaintFlow>::iterator TaintList::end() {
  if (!flows_) {
    return empty_taint_flow_vector.end();
  }
  return flows_->end();
}

std::vector<TaintFlow>::const_iterator TaintList::begin() const {
  if (!flows_) {
    return empty_taint_flow_vector.begin();
  }
  return flows_->begin();
}

std::vector<TaintFlow>::const_iterator TaintList::end() const {
  if (!flows_) {
    return empty_taint_flow_vector.end();
  }
  return flows_->end();
}

static bool IsE2EAlnum(char c) {
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
         (c >= 'A' && c <= 'Z');
}

static bool ParseE2ENumber(const std::string& s, uint32_t& out) {
  if (s.empty()) {
    return false;
  }
  uint32_t value = 0;
  for (char c : s) {
    if (c < '0' || c > '9') {
      return false;
    }
    value = value * 10 + static_cast<uint32_t>(c - '0');
  }
  out = value;
  return true;
}

static std::string ParseE2EQuotedString(const std::string& str, size_t& i,
                                        bool& valid) {
  char c = str[i];
  size_t pos = str.find(c, i + 1);
  if (pos == std::string::npos) {
    valid = false;
    return "";
  }
  valid = true;
  std::string res = str.substr(i + 1, pos - i - 1);
  i = pos + 1;
  return res;
}

static std::pair<std::string, std::string> ParseE2EKeyValuePair(
    const std::string& str, size_t& i, size_t length, bool& valid) {
  std::string key, value;
  bool expecting_value = false, parsing_value = false;
  valid = true;
  while (i < length) {
    char c = str[i];
    if (IsE2EAlnum(c)) {
      if (expecting_value) {
        parsing_value = true;
      }
      if (!parsing_value) {
        key.push_back(c);
      } else {
        value.push_back(c);
      }
    } else if (c == ':') {
      if (expecting_value) {
        break;
      }
      expecting_value = true;
    } else if (c == '\'' || c == '"') {
      if (!expecting_value) {
        break;
      }
      parsing_value = true;
      value = ParseE2EQuotedString(str, i, valid);
      break;
    } else if (parsing_value) {
      break;
    }
    i++;
  }
  if (!parsing_value) {
    valid = false;
  }
  return std::make_pair(key, value);
}

static bool ParseE2ERange(const std::string& str, size_t& i, size_t length,
                          StringTaint& taint, uint32_t& last_end) {
  i++;
  uint32_t begin = 0, end = 0;
  std::string source;
  bool have_begin = false, have_end = false, have_source = false;
  bool valid = true;
  while (i < length) {
    if (IsE2EAlnum(str[i])) {
      std::pair<std::string, std::string> kv =
          ParseE2EKeyValuePair(str, i, length, valid);
      if (!valid) {
        break;
      } else if (kv.first == "begin") {
        have_begin = ParseE2ENumber(kv.second, begin);
        if (!have_begin) {
          valid = false;
          break;
        }
      } else if (kv.first == "end") {
        have_end = ParseE2ENumber(kv.second, end);
        if (!have_end) {
          valid = false;
          break;
        }
      } else if (kv.first == "source") {
        have_source = true;
        source = kv.second;
      }
    } else if (str[i] == '}') {
      i++;
      break;
    } else {
      i++;
    }
  }
  if (!valid || !have_begin || !have_end || !have_source) {
    return false;
  }
  if (begin < last_end || end < begin) {
    return false;
  }
  TaintOperation op(source.c_str());
  op.setSource();
  TaintRange range = TaintRange(begin, end, TaintFlow(op));
  taint.append(range);
  last_end = end;
  return true;
}

static bool ParseStringTaintForE2ELegacy(const std::string& input,
                                         StringTaint& taint) {
  if (input.length() < 2 || input.front() != '[' || input.back() != ']') {
    return false;
  }
  taint.clear();
  size_t i = 1;
  size_t end = input.length() - 1;
  uint32_t last_end = 0;
  while (i < end) {
    if (input[i] == '{') {
      if (!ParseE2ERange(input, i, end, taint, last_end)) {
        taint.clear();
        return false;
      }
    } else {
      i++;
    }
  }
  return true;
}

bool ParseStringTaintForE2E(const std::string& input, StringTaint& taint) {
  json data = json::parse(input, nullptr, false);
  if (data.is_discarded()) {
    return ParseStringTaintForE2ELegacy(input, taint);
  }

  if (!data.is_array()) {
    return false;
  }

  uint32_t lastEnd = 0;

  taint.clear();

  for (const auto& elem : data) {
    if (!elem.is_object() ||
        (!elem.contains("begin") || !elem["begin"].is_number_unsigned()) ||
        (!elem.contains("end") || !elem["end"].is_number_unsigned()) ||
        (!elem.contains("source") || !elem["source"].is_string())) {
      return false;
    }

    uint32_t begin = elem["begin"].get<uint32_t>();
    uint32_t end = elem["end"].get<uint32_t>();
    std::string source = elem["source"].get<std::string>();

    TaintOperation op(source.c_str());
    op.setSource();
    TaintRange range = TaintRange(begin, end, TaintFlow(op));

    if (range.begin() < lastEnd) {
      return false;
    }
    taint.append(range);
    lastEnd = range.end();
  }

  return true;
}

StringTaint ParseStringTaintForE2E(const std::string& input) {
  StringTaint taint;
  return ParseStringTaintForE2E(input, taint) ? taint : EmptyTaint;
}

std::string SerializeStringTaintForE2E(const StringTaint& taint,
                                       bool addSinks) {
  json data = json::array();

  for (const auto& range : taint) {
    json rangeObj;
    rangeObj["begin"] = range.begin();
    rangeObj["end"] = range.end();
    rangeObj["source"] = range.flow().source().name();

    if (addSinks) {
      rangeObj["sink"] = range.flow().head()->operation().name();
    }

    data.push_back(std::move(rangeObj));
  }

  return data.dump();
}

StringTaint ParseStringTaint(std::string aInput) {
  json data = json::parse(aInput, nullptr, false);
  if (data.is_discarded()) {
    return EmptyTaint;
  }
  return LoadStringTaintFromJSON(data);
}

std::string SerializeStringTaint(const StringTaint& aTaint) {
  return DumpStringTaintAsJSON(aTaint).dump();
}

StringTaint LoadStringTaintFromJSON(const json& aData) {
  StringTaint taint;
  for (const auto& elem : aData) {
    taint.append(LoadTaintRangeFromJSON(elem));
  }
  return taint;
}

json DumpStringTaintAsJSON(const StringTaint& aTaint) {
  json data = json::array();
  for (const auto& range : aTaint) {
    data.push_back(DumpTaintRangeAsJSON(range));
  }
  return data;
}

TaintRange LoadTaintRangeFromJSON(const json& aData) {
  return TaintRange(aData[0].get<uint32_t>(), aData[1].get<uint32_t>(),
                    LoadTaintFlowFromJSON(aData[2]));
}

json DumpTaintRangeAsJSON(const TaintRange& aRange) {
  return json::array(
      {aRange.begin(), aRange.end(), DumpTaintFlowAsJSON(aRange.flow())});
}

TaintFlow LoadTaintFlowFromJSON(const json& aData) {
  TaintFlow flow;
  for (auto it = aData.rbegin(); it != aData.rend(); ++it) {
    flow.extend(LoadTaintOperationFromJSON(it.value()));
  }
  return flow;
}

json DumpTaintFlowAsJSON(const TaintFlow& aFlow) {
  json data = json::array();
  for (const auto& node : aFlow) {
    data.push_back(DumpTaintOperationAsJSON(node.operation()));
  }
  return data;
}

TaintOperation LoadTaintOperationFromJSON(const json& aData) {
  TaintOperation op(aData[0].get<std::string>().c_str(),
                    LoadTaintLocationFromJSON(aData[1]),
                    aData[2].get<std::vector<std::u16string>>());
  if (aData[3].get<bool>()) {
    op.setSource();
  }
  return op;
}

json DumpTaintOperationAsJSON(const TaintOperation& aOperation) {
  return json::array({
      aOperation.name(),
      DumpTaintLocationAsJSON(aOperation.location()),
      aOperation.arguments(),
      aOperation.isSource(),
  });
}

TaintLocation LoadTaintLocationFromJSON(const json& aData) {
  return TaintLocation(
      aData[0].get<std::u16string>(), aData[1].get<uint32_t>(),
      aData[2].get<std::uint32_t>(), aData[3].get<std::uint32_t>(),
      aData[4].get<std::uint32_t>(), aData[5].get<std::uint32_t>(),
      aData[6].get<TaintMd5>(), aData[7].get<std::u16string>());
}

json DumpTaintLocationAsJSON(const TaintLocation& aLocation) {
  return json::array({aLocation.filename(), aLocation.line(), aLocation.pos(),
                      aLocation.next_line(), aLocation.next_pos(),
                      aLocation.scriptStartLine(), aLocation.scriptHash(),
                      aLocation.function()});
}
