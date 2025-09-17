#!/bin/bash
# PostgreSQL Security Audit (read-only)

set -euo pipefail

# ---------- ПАРАМЕТРЫ ПОДКЛЮЧЕНИЯ ----------
PGUSER="${PGUSER:-postgres}"
PGDATABASE="${PGDATABASE:-postgres}"
PGHOST="${PGHOST:-}"
PGPORT="${PGPORT:-5432}"

PSQL_OPTS=()
[[ -n "$PGHOST" ]] && PSQL_OPTS+=( -h "$PGHOST" )
PSQL_OPTS+=( -p "$PGPORT" -U "$PGUSER" -d "$PGDATABASE" -AtX -v "ON_ERROR_STOP=1" )
PSQL="psql ${PSQL_OPTS[*]}"

# ---------- ВЫХОДНЫЕ ФАЙЛЫ ----------
TS="$(date +%F_%H%M%S)"
OUT_DIR="/tmp/pg_sec_audit_${TS}"
mkdir -p "$OUT_DIR"
SUMMARY="$OUT_DIR/summary.txt"

echo "PostgreSQL Security Audit — $TS" | tee "$SUMMARY"
echo "Output dir: $OUT_DIR" | tee -a "$SUMMARY"
echo | tee -a "$SUMMARY"

add_result () {
  # usage: add_result STATUS "Заголовок" "детали"
  local status="$1"; shift
  local title="$1"; shift
  local details="${1:-}"
  printf "%-6s | %s\n" "$status" "$title" | tee -a "$SUMMARY"
  [[ -n "$details" ]] && printf "        %s\n" "$details" >> "$SUMMARY"
}

sqlq () { # безопасный вызов psql
  set +e
  local out; out="$($PSQL -c "$1" 2>/dev/null)"; local rc=$?
  set -e
  [[ $rc -eq 0 ]] && printf "%s" "$out" || printf ""
}

save_csv () { # \copy SELECT ... TO file
  local query="$1"; local file="$2"
  $PSQL -c "\copy ($query) TO '$file' WITH CSV HEADER" >/dev/null 2>&1 || true
}

# ---------- 1) БАЗОВАЯ ИНФА / ВЕРСИЯ ----------
version_full="$(sqlq "SELECT version();")"
server_version_num="$(sqlq "SHOW server_version_num;")" || true
server_version_num="${server_version_num:-N/A}"

printf "%s\n" "$version_full" > "$OUT_DIR/version.txt"
printf "%s\n" "$server_version_num" > "$OUT_DIR/version_num.txt"

add_result "INFO" "PostgreSQL version (full)" "$version_full"

if [[ "$server_version_num" != "N/A" ]]; then
  add_result "OK" "PostgreSQL version (num)" "$server_version_num"
else
  add_result "WARN" "PostgreSQL version (num)" "Не удалось получить server_version_num"
fi

# ---------- 2) КЛЮЧЕВЫЕ НАСТРОЙКИ БЕЗОПАСНОСТИ ----------
save_csv "
  SELECT name, setting
  FROM pg_settings
  WHERE name LIKE 'log_%'
     OR name LIKE 'ssl_%'
     OR name IN ('password_encryption','hba_file','data_directory','listen_addresses','logging_collector')
  ORDER BY name" "$OUT_DIR/security_log_ssl.csv"

password_encryption="$(sqlq "SHOW password_encryption;")"
ssl="$(sqlq "SHOW ssl;")"
log_conn="$(sqlq "SHOW log_connections;")"
log_disconn="$(sqlq "SHOW log_disconnections;")"
logging_collector="$(sqlq "SHOW logging_collector;")"
listen_addresses="$(sqlq "SHOW listen_addresses;")"
data_directory="$(sqlq "SHOW data_directory;")"

# password_encryption
if [[ "$password_encryption" == "scram-sha-256" ]]; then
  add_result "OK" "password_encryption" "$password_encryption"
else
  add_result "FAIL" "password_encryption" "Текущее: '$password_encryption' (рекомендация: scram-sha-256)"
fi

# ssl
if [[ "$ssl" == "on" ]]; then
  add_result "OK" "ssl" "$ssl"
else
  add_result "FAIL" "ssl" "SSL выключен (рекомендовано: on)"
fi

# logging_collector
if [[ "$logging_collector" == "on" ]]; then
  add_result "OK" "logging_collector" "$logging_collector"
else
  add_result "WARN" "logging_collector" "Текущее: '$logging_collector' (рекомендовано: on)"
fi

# log_connections
if [[ "$log_conn" == "on" ]]; then
  add_result "OK" "log_connections" "$log_conn"
else
  add_result "WARN" "log_connections" "Текущее: '$log_conn' (рекомендовано: on)"
fi

# log_disconnections
if [[ "$log_disconn" == "on" ]]; then
  add_result "OK" "log_disconnections" "$log_disconn"
else
  add_result "WARN" "log_disconnections" "Текущее: '$log_disconn' (рекомендовано: on)"
fi

if [[ "$listen_addresses" == "*" ]]; then
  add_result "WARN" "listen_addresses = '*'" "Сервер слушает все интерфейсы. Ограничьте при необходимости."
else
  add_result "OK" "listen_addresses" "Текущее: $listen_addresses"
fi

# ---------- 3) ПОЛЬЗОВАТЕЛИ / РОЛИ ----------
save_csv "SELECT rolname, rolsuper, rolcreaterole, rolcreatedb, rolcanlogin FROM pg_roles" "$OUT_DIR/pg_roles.csv"
save_csv "
  SELECT
r.rolname AS role_name, string_agg(m.rolname, ', ' ORDER BY m.rolname) AS members
  FROM pg_auth_members am
  JOIN pg_roles r ON r.oid = am.roleid
  JOIN pg_roles m ON m.oid = am.member
  GROUP BY r.rolname
  ORDER BY r.rolname
" "$OUT_DIR/pg_role_members.csv"

superusers="$(sqlq "SELECT string_agg(rolname, ', ') FROM pg_roles WHERE rolsuper AND rolname <> 'postgres';")"
if [[ -n "$superusers" ]]; then
  add_result "WARN" "Доп. суперпользователи" "$superusers"
else
  add_result "OK" "Доп. суперпользователи" "Нет (кроме postgres)"
fi

# ---------- 4) РАСШИРЕНИЯ И preload-библиотеки ----------
save_csv "SELECT extname, extversion FROM pg_extension ORDER BY extname" "$OUT_DIR/pg_extensions.csv"
shared_preload="$(sqlq "SHOW shared_preload_libraries;")"
printf "%s\n" "$shared_preload" > "$OUT_DIR/shared_preload_libraries.txt"
add_result "OK" "shared_preload_libraries" "${shared_preload:-<пусто>}"

# ---------- 5) РЕПЛИКАЦИЯ ----------
save_csv "SELECT * FROM pg_stat_replication" "$OUT_DIR/pg_stat_replication.csv"
replicas_count="$(sqlq "SELECT count(*) FROM pg_stat_replication;")"
if [[ "${replicas_count:-0}" -gt 0 ]]; then
  add_result "OK" "Репликация" "Подключено реплик: $replicas_count"
else
  add_result "WARN" "Репликация" "Реплик не обнаружено (если это ОК — игнорируй)"
fi

# ---------- 6) pg_hba.conf ----------
hba_file="$(sqlq "SHOW hba_file;")"
printf "%s\n" "$hba_file" > "$OUT_DIR/hba_file_path.txt"

save_csv "
  SELECT setting AS hba_file,
         (pg_stat_file(setting)).size AS size,
         (pg_stat_file(setting)).modification AS modification,
         (pg_stat_file(setting)).change AS change,
         (pg_stat_file(setting)).isdir AS isdir
  FROM pg_settings WHERE name = 'hba_file'
" "$OUT_DIR/pg_hba_conf_info.csv"

$PSQL -c "\copy (SELECT unnest(string_to_array(pg_read_file(setting), E'\n')) AS hba_line FROM pg_settings WHERE name='hba_file') TO '$OUT_DIR/pg_hba_conf_full.csv' WITH CSV HEADER" >/dev/null 2>&1 || true

if [[ -f "$hba_file" ]]; then
  stat -c 'path:%n owner:%U group:%G mode:%a' "$hba_file" > "$OUT_DIR/pg_hba_permissions.txt" || true
  hba_owner="$(stat -c '%U' "$hba_file" 2>/dev/null || echo '?')"
  hba_group="$(stat -c '%G' "$hba_file" 2>/dev/null || echo '?')"
  hba_mode="$(stat -c '%a' "$hba_file" 2>/dev/null || echo '?')"
  hba_dir="$(dirname "$hba_file")"
  dir_mode="$(stat -c '%a' "$hba_dir" 2>/dev/null || echo '?')"
  [[ "$hba_owner" == "postgres" && "$hba_group" == "postgres" && "$hba_mode" == "600" && "$dir_mode" == "700" ]] \
    && add_result "OK" "pg_hba.conf права" "file=$hba_mode dir=$dir_mode owner=$hba_owner:$hba_group" \
    || add_result "FAIL" "pg_hba.conf права" "file=$hba_mode (ожид.600) dir=$dir_mode (ожид.700) owner=$hba_owner:$hba_group (ожид.postgres:postgres)"
else
  add_result "WARN" "pg_hba.conf права" "Файл недоступен в ОС ($hba_file)"
fi

# ---------- 7) DATA DIRECTORY ----------
printf "%s\n" "$data_directory" > "$OUT_DIR/data_directory_path.txt"
if [[ -n "$data_directory" && -d "$data_directory" ]]; then
  d_owner="$(stat -c '%U' "$data_directory" 2>/dev/null || echo '?')"
  d_group="$(stat -c '%G' "$data_directory" 2>/dev/null || echo '?')"
  d_mode="$(stat -c '%a' "$data_directory" 2>/dev/null || echo '?')"
  [[ "$d_owner" == "postgres" && "$d_group" == "postgres" && "$d_mode" == "700" ]] \
    && add_result "OK" "data_directory права" "$d_mode owner=$d_owner:$d_group" \
    || add_result "FAIL" "data_directory права" "$d_mode (ожид.700) owner=$d_owner:$d_group (ожид.postgres:postgres)"
else
  add_result "WARN" "data_directory права" "Каталог недоступен: $data_directory"
fi

# ---------- 8) ПРИВИЛЕГИИ ----------
save_csv "
  SELECT grantee, privilege_type, table_schema, table_name
  FROM information_schema.role_table_grants
" "$OUT_DIR/role_table_grants.csv"

# ---------- 9) CRON / SYSTEMD ----------
{ sudo -n -u "$PGUSER" crontab -l  crontab -l  echo "<нет crontab у $PGUSER>"; } > "$OUT_DIR/postgres_crontab.txt" 2>/dev/null || true
(systemctl list-timers --all 2>/dev/null | grep -i postgres  true) > "$OUT_DIR/systemd_timers.txt"  true

# ---------- 10) ИТОГ ----------
echo | tee -a "$SUMMARY"
echo "Детальные файлы: $OUT_DIR" | tee -a "$SUMMARY"

# ---------- 11) EXIT CODE ----------
if grep -q "^FAIL" "$SUMMARY"; then
  echo "[!] Найдены FAIL — см. $SUMMARY"
  exit 1
fi
