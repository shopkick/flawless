/**
 *  Author: jwegan@gmail.com (John Egan)
 */

enum LineType {
    DEFAULT = 1,
    KNOWN_ERROR = 2,
    BUILDING_BLOCK = 3,
    THIRDPARTY_WHITELIST = 4,
    IGNORED_FILEPATH = 5,
    BAD_FILEPATH = 6,
    RAISED_EXCEPTION = 7,
}

struct ErrorKey {
    1: string filename
    2: i64 line_number
    3: string function_name
    4: string text
}

struct StackLine {
    1: string filename
    2: i64 line_number
    3: string function_name
    4: string text
    5: map<string, string> frame_locals
}

struct RecordErrorRequest {
    1: list<StackLine> traceback
    2: string exception_message
    3: string hostname
    4: optional i64 error_threshold
    5: optional string additional_info
    6: optional i64 error_count
    7: string exception_type
}

struct ErrorInfo {
    1: i64 error_count
    2: string developer_email
    3: string date
    4: bool email_sent
    5: string last_occurrence
    6: bool is_known_error
    7: RecordErrorRequest last_error_data
}

struct EmailRemapping {
    1: map<string, string> remap = {}
    2: i64 last_update_ts
}

struct FileDisownershipEntry {
    1: string email
    2: string filepath
    3: string designated_email
}

struct FileDisownershipList {
    1: list<FileDisownershipEntry> disownerships = []
    2: i64 last_update_ts
}

struct WatchFileEntry {
    1: string email
    2: string filepath
    3: bool watch_all_errors
}

struct WatchList {
    1: list<WatchFileEntry> watches = []
    2: i64 last_update_ts
}

struct KnownError {
    1: string filename
    2: optional string function_name
    3: optional string code_fragment
    4: optional i64 min_alert_threshold
    5: optional i64 max_alert_threshold
    6: optional list<string> email_recipients
    7: optional string email_header
    8: optional i64 alert_every_n_occurrences
}

struct KnownErrorList {
    1: list<KnownError> identifiers = []
    2: i64 last_update_ts
}

struct CodeIdentifier {
    1: string filename
    2: optional string function_name
    3: optional string code_fragment
}

struct CodeIdentifierList {
    1: list<CodeIdentifier> identifiers = []
    2: i64 last_update_ts
}

struct IgnoredExceptionList {
    1: list<string> exceptions = []
    2: i64 last_update_ts
}

service Flawless {

    bool ping();
    
    void record_error(1: RecordErrorRequest request);

}