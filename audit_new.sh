#!/bin/bash
# PostgreSQL Security Audit (read-only) + CIS extras
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

# ---------- ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ----------
add_result () {
  local status="$1"; shift
  local title="$1"; shift
  local details="${1:-}"
  printf "%-6s | %s\n" "$status" "$title" | tee -a "$SUMMARY"
  [[ -n "$details" ]] && printf "        %s\n" "$details" | tee -a "$SUMMARY"
}

sqlq () {
  local out
  if ! out="$($PSQL -c "$1" 2>/dev/null)"; then
    echo ""
    return 0
  fi
  echo "$out"
}

save_csv () {
  local query="$1"; local file="$2"
  $PSQL -c "\copy ($query) TO '$file' WITH CSV HEADER" >/dev/null 2>&1 || true
}

# ---------- 1) ВЕРСИЯ ----------
version_full="$(sqlq "SELECT version();")"
server_version_num="$(sqlq "SHOW server_version_num;")" || true
server_version_num="${server_version_num:-N/A}"

add_result "INFO" "PostgreSQL version (full)" "$version_full"
add_result "OK"   "PostgreSQL version (num)"  "$server_version_num"

printf "%s\n" "$version_full"        > "$OUT_DIR/version.txt"
printf "%s\n" "$server_version_num"  > "$OUT_DIR/version_num.txt"

# ---------- 2) КЛЮЧЕВЫЕ НАСТРОЙКИ ----------
password_encryption="$(sqlq "SHOW password_encryption;")"
ssl="$(sqlq "SHOW ssl;")"
ssl_min="$(sqlq "SHOW ssl_min_protocol_version;")"
ssl_ciphers="$(sqlq "SHOW ssl_ciphers;")"
log_conn="$(sqlq "SHOW log_connections;")"
log_disconn="$(sqlq "SHOW log_disconnections;")"
logging_collector="$(sqlq "SHOW logging_collector;")"
listen_addresses="$(sqlq "SHOW listen_addresses;")"
data_directory="$(sqlq "SHOW data_directory;")"

# Блок логов (расширенный — CIS 3.x)
save_csv "
  SELECT name, setting
  FROM pg_settings
  WHERE name IN (
    'log_destination','logging_collector','log_directory','log_filename','log_file_mode',
    'log_truncate_on_rotation','log_rotation_age','log_rotation_size',
    'log_connections','log_disconnections','log_line_prefix','log_statement','log_timezone'
  )
  ORDER BY name
" "$OUT_DIR/logging_settings.csv"

# password_encryption (должен быть scram-sha-256)
if [[ "$password_encryption" == "scram-sha-256" ]]; then
  add_result "OK" "password_encryption" "$password_encryption"
else
  add_result "FAIL" "password_encryption" "Текущее: '$password_encryption' (рекомендовано: scram-sha-256)"
fi

# ssl
if [[ "$ssl" == "on" ]]; then
  add_result "OK" "ssl" "$ssl"
else
  add_result "FAIL" "ssl" "SSL выключен (рекомендовано: on)"
fi

# TLS минимум (рекомендовано не ниже TLSv1.2)
if [[ "$ssl" == "on" ]]; then
  if [[ "$ssl_min" =~ TLSv1\.2|TLSv1\.3 ]]; then
    add_result "OK" "ssl_min_protocol_version" "$ssl_min"
  else
    add_result "FAIL" "ssl_min_protocol_version" "Текущее: '$ssl_min' (рекомендовано: TLSv1.2+)"
  fi
  # Простейшая проверка на слабые шифры
  if echo "$ssl_ciphers" | grep -Eiq '(MD5|RC4|DES|3DES|EXPORT|NULL|aNULL)'; then
    add_result "FAIL" "ssl_ciphers" "Обнаружены слабые шифры в списке ('$ssl_ciphers') — очистите до безопасного набора"
  else
    add_result "OK" "ssl_ciphers" "$ssl_ciphers"
  fi
else
  add_result "WARN" "ssl_min_protocol_version / ssl_ciphers" "SSL=off — параметр не применяется"
fi

# logging settings
if [[ "$logging_collector" == "on" ]]; then
  add_result "OK" "logging_collector" "$logging_collector"
else
  add_result "WARN" "logging_collector" "Текущее: '$logging_collector' (рекомендовано: on)"
fi

if [[ "$log_conn" == "on" ]]; then
  add_result "OK" "log_connections" "$log_conn"
else
  add_result "WARN" "log_connections" "Рекомендовано включить"
fi

if [[ "$log_disconn" == "on" ]]; then
  add_result "OK" "log_disconnections" "$log_disconn"
else
  add_result "WARN" "log_disconnections" "Рекомендовано включить"
fi

# listen_addresses
if [[ "$listen_addresses" == "*" ]]; then
  add_result "WARN" "listen_addresses = '*'" "Сервер слушает все интерфейсы. Ограничьте при необходимости."
else
  add_result "OK" "listen_addresses" "$listen_addresses"
fi

# ---------- 3) РОЛИ / ЛИМИТЫ ПОДКЛЮЧЕНИЙ ----------
# Все роли и атрибуты
save_csv "SELECT rolname, rolsuper, rolcreaterole, rolcreatedb, rolcanlogin, rolconnlimit FROM pg_roles ORDER BY rolname" "$OUT_DIR/pg_roles.csv"

# Доп. суперпользователи
superusers="$(sqlq "SELECT string_agg(rolname, ', ') FROM pg_roles WHERE rolsuper AND rolname <> 'postgres';")"
if [[ -n "$superusers" ]]; then
  add_result "WARN" "Доп. суперпользователи" "$superusers"
else
  add_result "OK" "Доп. суперпользователи" "<нет>"
fi

# Роли-логины без лимита подключений (rolconnlimit = -1)
save_csv "
  SELECT rolname, rolconnlimit
  FROM pg_roles
  WHERE rolcanlogin AND rolconnlimit = -1
  ORDER BY rolname
" "$OUT_DIR/login_roles_no_connlimit.csv"
no_limit_count="$(wc -l < "$OUT_DIR/login_roles_no_connlimit.csv" | awk '{print ($1>1)?$1-1:0}')"
if [[ "$no_limit_count" -gt 0 ]]; then
  add_result "WARN" "CONNECTION LIMIT" "Логин-ролей без лимита: $no_limit_count (см. login_roles_no_connlimit.csv)"
else
  add_result "OK" "CONNECTION LIMIT" "Лимиты подключений настроены (или логин-ролей нет)"
fi

# ---------- 4) pgAudit ----------
pgaudit_present="$(sqlq "SELECT COUNT(*) FROM pg_extension WHERE extname='pgaudit';")"
if [[ "${pgaudit_present:-0}" -ge 1 ]]; then
  add_result "OK" "pgAudit" "Расширение установлено"
  save_csv "
    SELECT name, setting
    FROM pg_settings
    WHERE name LIKE 'pgaudit.%'
    ORDER BY name
  " "$OUT_DIR/pgaudit_settings.csv"
else
  add_result "WARN" "pgAudit" "Расширение не обнаружено (рекомендовано установить и настроить)"
fi

# ---------- 5) РЕПЛИКАЦИЯ И АРХИВИРОВАНИЕ ----------
replicas_count="$(sqlq "SELECT count(*) FROM pg_stat_replication;")"
if [[ "${replicas_count:-0}" -gt 0 ]]; then
  add_result "OK" "Репликация" "Подключено реплик: $replicas_count"
else
  add_result "WARN" "Репликация" "Реплик не обнаружено"
fi
save_csv "SELECT * FROM pg_stat_replication" "$OUT_DIR/pg_stat_replication.csv"

archive_mode="$(sqlq "SHOW archive_mode;")"
archive_command="$(sqlq "SHOW archive_command;")"
if [[ "$archive_mode" == "on" ]]; then
  if [[ -n "$archive_command" && "$archive_command" != "''" ]]; then
    add_result "OK" "WAL архивирование" "archive_mode=on; archive_command задан"
  else
    add_result "FAIL" "WAL архивирование" "archive_mode=on, но archive_command пуст"
  fi
else
  add_result "WARN" "WAL архивирование" "archive_mode=$archive_mode (для прод окружений обычно on)"
fi
printf "archive_mode=%s\narchive_command=%s\n" "$archive_mode" "$archive_command" > "$OUT_DIR/archive_settings.txt"

# ---------- 6) pg_hba.conf ----------
hba_file="$(sqlq "SHOW hba_file;")"
printf "%s\n" "$hba_file" > "$OUT_DIR/hba_file_path.txt"
if [[ -f "$hba_file" ]]; then
  hba_owner="$(stat -c '%U' "$hba_file" 2>/dev/null || echo '?')"
  hba_group="$(stat -c '%G' "$hba_file" 2>/dev/null || echo '?')"
  hba_mode="$(stat -c '%a' "$hba_file" 2>/dev/null || echo '?')"
  hba_dir="$(dirname "$hba_file")"
  dir_mode="$(stat -c '%a' "$hba_dir" 2>/dev/null || echo '?')"
  if [[ "$hba_owner" == "postgres" && "$hba_group" == "postgres" && "$hba_mode" == "600" && "$dir_mode" == "700" ]]; then
    add_result "OK" "pg_hba.conf права" "file=$hba_mode dir=$dir_mode owner=$hba_owner:$hba_group"
  else
    add_result "FAIL" "pg_hba.conf права" "file=$hba_mode (ожид.600) dir=$dir_mode (ожид.700) owner=$hba_owner:$hba_group (ожид.postgres:postgres)"
  fi
else
  add_result "WARN" "pg_hba.conf права" "Файл недоступен ($hba_file)"
fi

# Полное содержимое pg_hba.conf (если хватит прав)
$PSQL -c "\copy (
  SELECT unnest(string_to_array(pg_read_file(setting), E'\n')) AS hba_line
  FROM pg_settings WHERE name='hba_file'
) TO '$OUT_DIR/pg_hba_conf_full.csv' WITH CSV HEADER" >/dev/null 2>&1 || true

# ---------- 7) data_directory ----------
if [[ -n "$data_directory" && -d "$data_directory" ]]; then
  d_owner="$(stat -c '%U' "$data_directory" 2>/dev/null || echo '?')"
  d_group="$(stat -c '%G' "$data_directory" 2>/dev/null || echo '?')"
  d_mode="$(stat -c '%a' "$data_directory" 2>/dev/null || echo '?')"
  if [[ "$d_owner" == "postgres" && "$d_group" == "postgres" && "$d_mode" == "700" ]]; then
    add_result "OK" "data_directory права" "$d_mode owner=$d_owner:$d_group"
  else
    add_result "FAIL" "data_directory права" "$d_mode (ожид.700) owner=$d_owner:$d_group (ожид.postgres:postgres)"
  fi
else
  add_result "WARN" "data_directory права" "Каталог недоступен: $data_directory"
fi

# ---------- 8) ПРИВИЛЕГИИ / ДЕТАЛИ (CSV) ----------
save_csv "
  SELECT r.rolname AS role_name,
         string_agg(m.rolname, ', ' ORDER BY m.rolname) AS members
  FROM pg_auth_members am
  JOIN pg_roles r ON r.oid = am.roleid
  JOIN pg_roles m ON m.oid = am.member
  GROUP BY r.rolname
  ORDER BY r.rolname
" "$OUT_DIR/pg_role_name.csv"

save_csv "SELECT * FROM pg_user" "$OUT_DIR/pg_user.csv"
save_csv "SELECT * FROM pg_user_mapping" "$OUT_DIR/pg_user_mapping.csv"
save_csv "SELECT * FROM pg_auth_members" "$OUT_DIR/pg_auth_members.csv"

save_csv "
  SELECT grantee, privilege_type, table_schema, table_name
  FROM information_schema.role_table_grants
" "$OUT_DIR/pg_role_table_grants.csv"

save_csv "SELECT extname, extversion FROM pg_extension ORDER BY extname" "$OUT_DIR/pg_extensions.csv"

# ---------- 9) CRON / SYSTEMD ----------
{ sudo -n -u "$PGUSER" crontab -l || crontab -l || echo "<нет crontab у $PGUSER>"; } > "$OUT_DIR/postgres_crontab.txt" 2>/dev/null || true
(systemctl list-timers --all 2>/dev/null | grep -i postgres || true) > "$OUT_DIR/systemd_timers.txt" || true

# ---------- 10) CIS: PGPASSWORD НЕ ИСПОЛЬЗУЕТСЯ ----------
# По профилям пользователей/скелетам
{
  grep -RIn --binary-files=without-match -E '\bPGPASSWORD=' /etc/skel /home /root 2>/dev/null || true
} > "$OUT_DIR/pgpassword_in_profiles.txt" || true
# В окружении процессов postgres
: > "$OUT_DIR/pgpassword_in_process_env.txt"
for pid in $(pgrep -u postgres -f . 2>/dev/null || true); do
  if tr '\0' '\n' < "/proc/$pid/environ" 2>/dev/null | grep -q '^PGPASSWORD='; then
    echo "PID=$pid CMD=$(tr '\0' ' ' < /proc/$pid/cmdline 2>/dev/null)" >> "$OUT_DIR/pgpassword_in_process_env.txt"
  fi
done

pgpw_prof_sz=$(wc -c < "$OUT_DIR/pgpassword_in_profiles.txt" || echo 0)
pgpw_env_sz=$(wc -c < "$OUT_DIR/pgpassword_in_process_env.txt" || echo 0)

if [[ "$pgpw_prof_sz" -eq 0 && "$pgpw_env_sz" -eq 0 ]]; then
  add_result "OK" "PGPASSWORD" "Не обнаружен ни в профилях, ни в окружении процессов"
else
  add_result "FAIL" "PGPASSWORD" "Найден (см. pgpassword_in_profiles.txt / pgpassword_in_process_env.txt)"
fi

# ---------- 11) ИТОГ ----------
echo | tee -a "$SUMMARY"
echo "Детальные файлы: $OUT_DIR" | tee -a "$SUMMARY"

if grep -q "^FAIL" "$SUMMARY"; then
  echo "[!] Найдены FAIL — см. $SUMMARY"
  exit 1
fi
