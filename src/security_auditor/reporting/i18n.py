"""Small HTML-only zh-TW display catalog; machine contracts are unchanged."""

HTML_LOCALE = "zh-TW"

MESSAGES = {
    "scope": "掃描範圍與排除項目",
    "excluded_directories": "排除的目錄",
    "excluded_files": "排除的檔案",
    "default_exclusions": "套用預設排除",
    "scope_note": "以下項目依可信任的掃描範圍設定排除；未檢查其內容，也不計為掃描失敗。",
    "scope_more": "其他排除項目未逐一列出",
    "scope_complete": "已完成目前掃描範圍內的分析。",
    "title": "本機安全掃描器",
    "target": "掃描目標",
    "profile": "掃描設定檔",
    "offline": "離線模式",
    "coverage": "掃描覆蓋率",
    "partial_warning": "警告：本次掃描覆蓋範圍不完整，下列安全問題數量不代表整個專案的完整狀態。",
    "aborted_warning": "掃描已中止，結果僅代表中止前完成分析的範圍。",
    "failed_warning": "掃描未能完成，請先查看診斷資訊。",
    "truncated_warning": "警告：報告內容因安全資源上限而截斷，實際掃描結果數量可能多於目前顯示的項目。",
    "summary": "掃描摘要",
    "zero_findings": "在已完成分析的範圍內未偵測到安全問題。",
    "total": "總數",
    "rendered": "顯示數",
    "risk_priorities": "風險優先級",
    "findings": "確定性掃描結果",
    "groups": "問題群組",
    "attack_paths": "潛在攻擊路徑",
    "dependencies": "依賴套件漏洞",
    "packages": "套件數",
    "exact_versions": "確切版本",
    "first_party_roots": "第一方專案根套件",
    "unresolved_third_party": "未解析的第三方依賴",
    "no_data": "無漏洞資料",
    "matches": "漏洞命中",
    "ai": "AI 輔助審查",
    "ai_advisory": "AI 輔助審查僅供參考，不會覆寫確定性掃描結果。",
    "status": "狀態",
    "reviewed": "已審查",
    "eligible": "個符合審查條件的項目",
    "remediation": "修復建議",
    "proposal_not_applied": "修復提案尚未套用至原始程式碼。",
    "runtime_not_run": "未執行執行階段測試。",
    "human_approval": "所有修復提案均須經人工確認。",
    "coverage_diagnostics": "掃描覆蓋率與診斷",
    "skipped": "略過檔案",
    "limits": "觸發資源限制",
    "privacy": "隱私與外部服務",
    "osv": "使用 OSV 線上漏洞查詢",
    "gemini": "使用 Gemini AI",
    "privacy_note": "只有在使用者明確啟用 AI 輔助審查時，才會傳送經過範圍限制與敏感資訊遮蔽的內容。",
    "no_gemini": "本次掃描未將原始碼內容傳送至 Gemini。",
    "severity": "嚴重程度",
    "confidence": "信心程度",
    "risk_priority": "風險優先級",
    "rule": "規則",
    "location": "位置",
    "evidence": "證據",
    "primary": "主要安全問題",
    "supporting": "支援性安全訊號",
    "none": "無",
    "unassessed": "未評估",
    "related_proposal": "相關修復提案",
    "assumption": "假設",
    "file": "檔案",
    "static_validation": "靜態驗證",
    "runtime_tests": "執行階段測試",
    "approval_required": "必須經人工確認",
    "limitations": "分析限制",
}

VALUES = {
    "COMPLETE": "完整", "PARTIAL": "部分完成", "ABORTED": "已中止", "FAILED": "失敗",
    "DISABLED": "未啟用", "complete": "完整", "partial": "部分完成",
    "aborted": "已中止", "failed": "失敗", "disabled": "未啟用",
    "CRITICAL": "嚴重", "HIGH": "高", "MEDIUM": "中", "LOW": "低", "INFO": "資訊",
    "critical": "嚴重", "high": "高", "medium": "中", "low": "低", "info": "資訊",
    "quick": "快速", "standard": "標準", "deep": "深入",
    "discovery": "檔案探索", "secrets": "機密資訊掃描",
    "sast.python": "Python 靜態程式碼分析", "behavior.static": "危險行為分析",
    "dependencies": "依賴套件分析", "correlation": "關聯分析", "ai": "AI 輔助審查",
    "primary": "主要安全問題", "supporting": "支援性安全訊號",
    "contextual": "情境訊號", "duplicate": "重複訊號",
    "vulnerability": "安全問題", "secret": "機密資訊",
    "behavior": "危險行為訊號", "dependency": "依賴套件",
    "config": "設定問題",
    "GUIDANCE_ONLY": "僅提供修復指引", "DETERMINISTIC": "確定性修復提案",
    "AI_ASSISTED": "AI 輔助修復提案", "VALIDATED_STATICALLY": "已通過靜態驗證",
    "PARTIAL_VALIDATION": "僅完成部分靜態驗證", "REJECTED": "提案已拒絕",
    "NOT_RUN": "未執行", "NO_DATA": "無可用漏洞資料",
    "NO_MATCH": "未找到符合的已知漏洞", "OFFLINE_NO_CACHE": "離線模式且無可用快取資料",
    "QUERY_FAILED": "漏洞資料查詢失敗", "Direct": "直接依賴",
    "Transitive": "間接依賴", "Unknown": "未知",
    "CONFIRMED": "AI 判斷：證據高度支持", "LIKELY_VALID": "AI 判斷：較可能成立",
    "UNCERTAIN": "AI 判斷：不確定", "LIKELY_FALSE_POSITIVE": "AI 判斷：較可能為誤報",
    "INSUFFICIENT_CONTEXT": "AI 判斷：資訊不足",
    "Potential local download-and-execute sequence": "潛在下載並執行路徑",
    "Potential persistence-related execution context": "潛在持續性執行情境",
}

DIAGNOSTICS = {
    "SAST_AST_NODE_LIMIT_REACHED": "Python AST 節點數已達安全分析上限。",
    "SAST_AST_DEPTH_LIMIT_REACHED": "Python AST 深度已達安全分析上限。",
    "BEHAVIOR_AST_NODE_LIMIT_REACHED": "Python AST 節點數已達危險行為分析的安全上限。",
    "BEHAVIOR_AST_DEPTH_LIMIT_REACHED": "Python AST 深度已達危險行為分析的安全上限。",
    "SAST_FILE_TOO_LARGE": "Python 檔案超過靜態分析的單檔大小上限。",
    "SAST_TOTAL_BYTE_BUDGET_REACHED": "靜態分析已達總讀取位元組上限。",
    "SAST_PARSE_FAILED": "Python 原始碼無法安全解析。",
    "SAST_FUNCTION_LIMIT_REACHED": "Python 函式分析已達節點上限。",
    "SAST_FINDING_LIMIT_REACHED": "靜態分析已達安全問題數量上限。",
    "SAST_ANALYSIS_TIMEOUT": "靜態分析已達時間上限。",
    "SAST_RULE_ERROR": "靜態分析規則處理失敗。",
    "SAST_UNSUPPORTED_ENCODING": "Python 檔案編碼無法解讀。",
    "SAST_READ_FAILED": "無法安全讀取已納入的 Python 檔案。",
    "SAST_DISCOVERY_INCOMPLETE": "檔案探索未完整完成。",
    "BEHAVIOR_FILE_TOO_LARGE": "檔案超過危險行為分析的單檔大小上限。",
    "BEHAVIOR_TOTAL_BYTE_BUDGET_REACHED": "危險行為分析已達總讀取位元組上限。",
    "BEHAVIOR_LINE_TOO_LONG": "文字行超過危險行為分析上限。",
    "BEHAVIOR_MATCH_LIMIT_REACHED": "危險行為分析已達命中或結果數量上限。",
    "BEHAVIOR_RULE_ERROR": "危險行為分析規則處理失敗。",
    "BEHAVIOR_ANALYSIS_TIMEOUT": "危險行為分析已達時間上限。",
    "BEHAVIOR_PARSE_FAILED": "Python 原始碼無法供危險行為分析安全解析。",
    "BEHAVIOR_UNSUPPORTED_ENCODING": "危險行為分析無法解讀檔案編碼。",
    "BEHAVIOR_READ_FAILED": "無法安全讀取已納入的檔案。",
    "BEHAVIOR_DISCOVERY_INCOMPLETE": "檔案探索未完整完成。",
    "SECRET_FILE_TOO_LARGE": "檔案超過機密資訊掃描的單檔大小上限。",
    "SECRET_SCAN_BYTE_BUDGET_REACHED": "機密資訊掃描已達總讀取位元組上限。",
    "SECRET_MATCH_LIMIT_REACHED": "機密資訊掃描已達命中或結果數量上限。",
    "SECRET_LINE_TOO_LONG": "文字行超過機密資訊掃描上限。",
    "SECRET_DECODE_UNAVAILABLE": "無法解讀檔案文字編碼。",
    "SECRET_READ_FAILED": "無法安全讀取已納入的檔案。",
    "SECRET_RULE_ERROR": "機密資訊掃描規則處理失敗。",
    "SECRET_SCAN_ABORTED": "機密資訊掃描已達時間上限。",
    "SECRET_DISCOVERY_INCOMPLETE": "檔案探索未完整完成。",
    "SECRET_PRIVATE_KEY_UNTERMINATED": "私鑰起始標記缺少對應結束標記。",
    "SECRET_FINGERPRINT_COLLISION": "遮蔽後的問題位置發生衝突，已指派不同的安全識別碼。",
    "DEPENDENCY_DISCOVERY_INCOMPLETE": "檔案探索未完整完成。",
    "DEPENDENCY_PARSE_FAILED": "依賴套件檔案無法安全解析。",
    "DEPENDENCY_UNSUPPORTED_FORMAT": "目前版本不支援此依賴套件格式。",
    "DEPENDENCY_UNRESOLVED_VERSION": "套件版本不夠精確，無法推定漏洞是否命中。",
    "DEPENDENCY_INCLUDE_OUTSIDE_ROOT": "依賴檔引用目標根目錄外或未納入的檔案。",
    "DEPENDENCY_INCLUDE_LOOP": "依賴檔引用發生循環或達到深度上限。",
    "DEPENDENCY_FILE_TOO_LARGE": "依賴套件檔案超過單檔大小上限。",
    "DEPENDENCY_BYTE_LIMIT_REACHED": "依賴套件分析已達總讀取位元組上限。",
    "DEPENDENCY_ENTRY_LIMIT_REACHED": "依賴套件項目已達數量上限。",
    "DEPENDENCY_QUERY_LIMIT_REACHED": "漏洞資料查詢已達數量上限。",
    "DEPENDENCY_PROVIDER_NO_DATA": "確切版本沒有可用的漏洞資料。",
    "DEPENDENCY_PROVIDER_FAILED": "漏洞資料來源未回傳完整資料。",
    "DEPENDENCY_CACHE_CORRUPT": "漏洞資料快取項目無效。",
    "DEPENDENCY_CACHE_STALE": "使用了過期的漏洞資料快取。",
    "DEPENDENCY_CACHE_READ_FAILED": "無法讀取漏洞資料快取。",
    "DEPENDENCY_CACHE_WRITE_FAILED": "無法安全寫入漏洞資料快取。",
    "DEPENDENCY_UNSUPPORTED_ECOSYSTEM": "此套件生態系尚無設定的漏洞資料來源。",
    "DEPENDENCY_READ_FAILED": "無法安全讀取已納入的依賴套件檔案。",
    "DEPENDENCY_TIMEOUT": "依賴套件分析已達時間上限。",
    "VULN_PROVIDER_TIMEOUT": "漏洞資料來源查詢逾時。",
    "VULN_PROVIDER_NETWORK_ERROR": "漏洞資料來源網路查詢失敗。",
    "VULN_PROVIDER_BAD_RESPONSE": "漏洞資料來源回應無效或不完整。",
    "VULN_PROVIDER_RESPONSE_TOO_LARGE": "漏洞資料來源回應超過大小上限。",
    "VULN_PROVIDER_RATE_LIMITED": "漏洞資料來源限制了查詢頻率。",
    "AI_OFFLINE": "離線模式未啟用 AI 輔助審查。",
    "FILE_TOO_LARGE": "檔案超過探索大小上限。",
    "SCAN_CANCELLED": "掃描已由使用者中止。",
}


SCOPE_CLASSES = {
    "CACHE": "快取目錄",
    "ENVIRONMENT": "虛擬環境",
    "DEPENDENCY_VENDOR": "第三方依賴目錄",
    "BUILD_OUTPUT": "建置輸出",
    "GENERATED": "產生式資料",
    "UNKNOWN": "依設定排除",
}


def scope_label(scope_class: str) -> str:
    return SCOPE_CLASSES.get(scope_class, SCOPE_CLASSES["UNKNOWN"])


def message(key: str) -> str:
    return MESSAGES[key]


def display(value: object) -> str:
    if isinstance(value, bool):
        return "是" if value else "否"
    if value is None:
        return MESSAGES["none"]
    return VALUES.get(str(value), str(value))


def scanner_label(scanner_id: str) -> str:
    label = VALUES.get(scanner_id)
    return f"{label} ({scanner_id})" if label else scanner_id


def diagnostic_message(code: str, fallback: str) -> str:
    return DIAGNOSTICS.get(code, "請依診斷代碼檢查掃描覆蓋率與來源資料狀態。")
