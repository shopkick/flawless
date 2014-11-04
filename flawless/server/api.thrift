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


service Flawless {

    bool ping();
    
    void record_error(1: RecordErrorRequest request);

}