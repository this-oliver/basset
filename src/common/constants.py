DEFAULT_METHODS = "GET"
DEFAULT_STATUS = "200,301"

SAFE_HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "TRACE"]
SAFE_MEDIA_EXTENSIONS = [".jpg", ".jpeg", ".png", ".svg", ".webp", ".ico", ".gif", ".mp3", ".mp4", ".mov", ".avi", ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".zip"]

UNSAFE_PHP_FILES = ["config.php", "db.php", "auth.php", "shell.php", "cmd.php", "backup.php", "connect.php", "index_backup.php", "main.php", "upload.php", "reset.php", "install.php"]
