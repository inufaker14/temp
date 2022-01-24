#!/bin/bash

# 전역변수 설정
__HOST__="localhost"
__PORT__=3306
__UID__="root"
__UPW__=""
__CLIENT__="mysql" #mysql 클라이언트 Path
__MYCONN__=""
__DEBUGMODE__=0

# 전역변수 - 파일명 설정
__FILEHD__=$(hostname -s)'_mysql'
__RESULT__=$__FILEHD__.txt
__RAWLOG__=$__FILEHD__'_RAW.txt'

rm -f $__RESULT__

__Clients__=$(find / -type f -executable -iname mysql 2>/dev/null)
for Client in $__Clients__
do
  $Client --help | grep -i 'mysql' > /dev/null
  if [ $? -eq 0 ]; then
    __CLIENT__=$Client
    break
  fi
done

# MySQL 연결 값 입력 받음 처리
echo "#####################################################################################################################"
echo "#  진단 진행을 위한 Connection 정보를 입력받습니다."
echo "#####################################################################################################################"

# =~는 기본적으로 없는 시스템이 있음
#if [[ "$__CLIENT__" =~ ^(mysql|\s)*$ ]]; then
#  echo -n "MySQL Client Path (0/4 - default:mysql) : "
#  read client
#fi

if [ -e "$__CLIENT__" ]; then
  client=$__CLIENT__;
else
  echo -n "MySQL Client Path (0/4 - default:mysql) : "
  read client
fi

echo -n "MySQL Host (1/4 - default:$__HOST__) : "
read host
echo -n "MySQL Port (2/4 - default:$__PORT__) : "
read port
echo -n "MySQL Admin ID (3/4 - default:$__UID__) : "
read id
echo -n "MySQL Admin Password (4/4) : "
read pw

# 연결 값 입력 검증 및 전역변수로 대입
if [ "$client" != "" ]; then
  __CLIENT__=$client;
fi

if [ "$host" != "" ]; then
  __HOST__=$host;
fi

if [ "$port" != "" ]; then
  if [ $port -ge 1 ] || [ $port -le 65535 ]
  then
    __PORT__=$port;
  fi
fi

if [ "$id" != "" ]; then
  __UID__=$id;
fi

if [ "$pw" != "" ]; then
  __UPW__=$pw;
else
  # 패스워드가 비어 있는 경우 종료
  echo "Connection Fail_1";
  exit;
fi

# MySQL 실행명령어 초기화
__MYCONN__="$__CLIENT__ -h $__HOST__ -P $__PORT__ -u $__UID__ -p$__UPW__";

# Connection 체크
$__MYCONN__ --skip-column-names -B -e "SELECT SUBSTRING_INDEX(Version(), '-', 1)"
if [ $? -eq 1 ]; then
  echo "Connection Fail_2";
  exit;
fi

# 버전정보 수집
__DBVER__=$($__MYCONN__ --skip-column-names -B -e "SELECT SUBSTRING_INDEX(Version(), '-', 1)");
if [[ $(echo "$__DBVER__" | grep '[0-9]\+\.[0-9]\+\.\?[0-9]\?') == "" ]]; then
  echo "Connection Fail_3";
  exit;
fi

# 특목 버전 확인
__IS55MORE__=$($__MYCONN__ --skip-column-names -B -e "SELECT SUBSTRING_INDEX(Version(), '-', 1) >= '5.5.0'");
__IS57MORE__=$($__MYCONN__ --skip-column-names -B -e "SELECT SUBSTRING_INDEX(Version(), '-', 1) >= '5.7.0'");

# 최신 버전 정보 ( 최신버전 갱신시 https://dev.mysql.com/doc/relnotes/mysql/8.0/en/ 내 mysql 버전별 릴리즈 참조 )
__55LAT__="5.5.62";
__56LAT__="5.6.45";
__57LAT__="5.7.27";
__80LAT__="8.0.17";

echo "■ DB-01. 기본 계정의 패스워드, 정책 등을 변경하여 사용" >> $__RESULT__;
echo "■ 기준 : 기본 계정의 패스워드를 변경하여 사용하는 경우 양호" >> $__RESULT__;
echo "■ 현황" >> $__RESULT__;

if [ $__IS55MORE__ -eq 1 ]; then
  if [ $__IS57MORE__ -eq 1 ]; then
    $__MYCONN__ --skip-column-names -B -e "SELECT CONCAT('DB-01', ',', (IF (COUNT(T.user) > 0, 'X', 'O')), ',,') AS '' FROM (SELECT DISTINCT user, plugin, authentication_string FROM mysql.user WHERE user <> '' GROUP BY user) T WHERE plugin = 'mysql_native_password' AND (authentication_string = password('') OR authentication_string = password(T.user));" >> $__RESULT__;
    $__MYCONN__ --skip-column-names -B -e "SELECT CASE WHEN (SELECT COUNT(user) FROM (SELECT DISTINCT user, plugin, authentication_string FROM mysql.user WHERE user <> '' GROUP BY user) T WHERE plugin = 'mysql_native_password' AND (authentication_string = Password('') OR authentication_string = password(T.user)) > 0) \
      THEN '패스워드가 취약한(미설정 또는 아이디와 동일) 계정이 존재함' \
      ELSE '패스워드가 취약한(미설정 또는 아이디와 동일) 계정이 발견되지 않음' END AS ''" >> $__RESULT__;
    $__MYCONN__ -B -e "SELECT DISTINCT user, plugin, authentication_string, (authentication_string = password(user)) passwordSameId FROM mysql.user WHERE user <> '' GROUP BY user;" >> $__RESULT__;
  else
    $__MYCONN__ --skip-column-names -B -e "SELECT CONCAT('DB-01', ',', (IF (COUNT(T.user) > 0, 'X', 'O')), ',,') AS '' FROM (SELECT DISTINCT user, password, plugin, authentication_string FROM mysql.user WHERE user <> '' GROUP BY user) T WHERE (plugin IS NULL AND password = password('')) OR (plugin = 'mysql_native_password' AND (authentication_string = password('') OR authentication_string = password(T.user)));" >> $__RESULT__;
    $__MYCONN__ --skip-column-names -B -e "SELECT CASE WHEN (SELECT COUNT(user) FROM (SELECT DISTINCT user, password, plugin, authentication_string FROM mysql.user WHERE user <> '' GROUP BY user) T WHERE (plugin IS NULL AND password = Password('')) OR (plugin = 'mysql_native_password' AND (authentication_string = Password('') OR authentication_string = password(T.user))) > 0) \
      THEN '패스워드가 취약한(미설정 또는 아이디와 동일) 계정이 존재함' \
      ELSE '패스워드가 취약한(미설정 또는 아이디와 동일) 계정이 발견되지 않음' END AS ''" >> $__RESULT__;
    $__MYCONN__ -B -e "SELECT DISTINCT user, password, plugin, authentication_string, (authentication_string = password(user)) passwordSameId FROM mysql.user WHERE user <> '' GROUP BY user;" >> $__RESULT__;
  fi
else
  $__MYCONN__ --skip-column-names -B -e "SELECT CONCAT('DB-01', ',', (IF (COUNT(T.user) > 0, 'X', 'O')), ',,') AS '' FROM (SELECT DISTINCT user, password FROM mysql.user WHERE user <> '' GROUP BY user) T WHERE T.password = password('') OR T.password = password(user);" >> $__RESULT__;
  $__MYCONN__ --skip-column-names -B -e "SELECT CASE WHEN((SELECT COUNT(T.user) FROM (SELECT DISTINCT user, password FROM mysql.user WHERE user <> '' GROUP BY user) T WHERE T.password = password('') OR T.password = password(user)) > 0) \
    THEN '패스워드가 취약한(미설정 또는 아이디와 동일) 계정이 존재함' \
    ELSE '패스워드가 취약한(미설정 또는 아이디와 동일) 계정이 발견되지 않음' END AS '';" >> $__RESULT__;
  $__MYCONN__ -B -e "SELECT DISTINCT user, password FROM mysql.user WHERE user <> '' GROUP BY user" >> $__RESULT__;
fi
echo '' >> $__RESULT__;


echo "■ DB-02. scott 등 Demonstration 및 불필요 계정을 제거하거나 잠금 설정 후 사용" >> $__RESULT__;
echo "■ 기준 : 계정 정보를 확인하여 불필요한 계정이 없는 경우 양호" >> $__RESULT__;
echo "■ 현황" >> $__RESULT__;

echo "DB-02,C,," >> $__RESULT__;
echo "[수동진단]사용하지 않는 계정에 대한 인터뷰 필요" >> $__RESULT__;
$__MYCONN__ -e "SELECT u.user, d.db FROM mysql.user u LEFT JOIN mysql.db d ON u.user = d.user WHERE u.user <> '' GROUP BY u.user" >> $__RESULT__;

$__MYCONN__ -e "SELECT u.user, d.db FROM mysql.user u LEFT JOIN mysql.db d ON u.user = d.user WHERE u.user <> '' GROUP BY u.user"
echo '' >> $__RESULT__;


echo "■ DB-03. 패스워드의 사용기간 및 복잡도 기관 정책에 맞도록 설정" >> $__RESULT__;
echo "■ 기준 : 패스워드를 주기적으로 변경하고, 패스워드 정책이 적용되어 있는 경우 양호" >> $__RESULT__;
echo "■ 현황" >> $__RESULT__;

echo "DB-03,C,, "  >> $__RESULT__;
echo "[수동진단]" >> $__RESULT__;
echo '' >> $__RESULT__;


echo "■ DB-04. 데이터베이스 관리자 권한을 꼭 필요한 계정 및 그룹에 허용" >> $__RESULT__;
echo "■ 기준 : 계정 별 관리자 권한이 차등 부여 되어 있는 경우 양호" >> $__RESULT__;
echo "■ 현황" >> $__RESULT__;

$__MYCONN__ --skip-column-names -B -e "SELECT CONCAT('DB-04', ',', (IF (COUNT(T.user) > 0, 'X', 'O')), ',,') AS '' FROM (SELECT User, Select_priv, Insert_priv, Update_priv, Delete_priv, Create_priv, Drop_priv, Reload_priv, Shutdown_priv, Process_priv, File_priv, Grant_priv, References_priv, Index_priv, Alter_priv, Show_db_priv, Super_priv, Create_tmp_table_priv, Lock_tables_priv, Execute_priv, Repl_slave_priv, Repl_client_priv, Create_view_priv, Show_view_priv, Create_routine_priv, Alter_routine_priv, Create_user_priv, Event_priv, Trigger_priv FROM mysql.user WHERE 'Y' IN (Select_priv, Insert_priv, Update_priv, Delete_priv, Create_priv, Drop_priv, Reload_priv, Shutdown_priv, Process_priv, File_priv, Grant_priv, References_priv, Index_priv, Alter_priv, Show_db_priv, Super_priv, Create_tmp_table_priv, Lock_tables_priv, Execute_priv, Repl_slave_priv, Repl_client_priv, Create_view_priv, Show_view_priv, Create_routine_priv, Alter_routine_priv, Create_user_priv, Event_priv, Trigger_priv) GROUP BY user) T WHERE T.user <> 'root';" >> $__RESULT__;
$__MYCONN__ --skip-column-names -B -e "SELECT CASE WHEN ((SELECT COUNT(User) FROM mysql.user WHERE 'Y' IN (Select_priv, Insert_priv, Update_priv, Delete_priv, Create_priv, Drop_priv, Reload_priv, Shutdown_priv, Process_priv, File_priv, Grant_priv, References_priv, Index_priv, Alter_priv, Show_db_priv, Super_priv, Create_tmp_table_priv, Lock_tables_priv, Execute_priv, Repl_slave_priv, Repl_client_priv, Create_view_priv, Show_view_priv, Create_routine_priv, Alter_routine_priv, Create_user_priv, Event_priv, Trigger_priv) AND user <> 'root' GROUP BY user) > 0) \
   THEN 'ROOT 외 관리권한이 부여된 계정이 존재함' \
   ELSE 'ROOT 외 관리권한이 부여된 계정이 발견되지 않음' END AS '';" >> $__RESULT__;
$__MYCONN__ -B -e "SELECT User, Select_priv, Insert_priv, Update_priv, Delete_priv, Create_priv, Drop_priv, Reload_priv, Shutdown_priv, Process_priv, File_priv, Grant_priv, References_priv, Index_priv, Alter_priv, Show_db_priv, Super_priv, Create_tmp_table_priv, Lock_tables_priv, Execute_priv, Repl_slave_priv, Repl_client_priv, Create_view_priv, Show_view_priv, Create_routine_priv, Alter_routine_priv, Create_user_priv, Event_priv, Trigger_priv FROM mysql.user WHERE 'Y' IN (Select_priv, Insert_priv, Update_priv, Delete_priv, Create_priv, Drop_priv, Reload_priv, Shutdown_priv, Process_priv, File_priv, Grant_priv, References_priv, Index_priv, Alter_priv, Show_db_priv, Super_priv, Create_tmp_table_priv, Lock_tables_priv, Execute_priv, Repl_slave_priv, Repl_client_priv, Create_view_priv, Show_view_priv, Create_routine_priv, Alter_routine_priv, Create_user_priv, Event_priv, Trigger_priv) GROUP BY user;" >> $__RESULT__;
echo '' >> $__RESULT__;

echo "■ DB-12. 패스워드 재사용에 대한 제약" >> $__RESULT__;
echo "■ 기준 : PASSWORD_REUSE_TIME, PASSWORD_REUSE_MAX 파라미터 설정이 적용된 경우 양호" >> $__RESULT__;
echo "■ 현황" >> $__RESULT__;

echo "DB-12,N/A,," >> $__RESULT__;
echo "Oracle 환경에 대한 설정부분으로 해당사항 없음" >> $__RESULT__;
echo '' >> $__RESULT__;

echo "■ DB-13. DB 사용자 계정 개별적 부여" >> $__RESULT__;
echo "■ 기준 : 사용자별 계정을 사용하고 있는 경우 양호" >> $__RESULT__;
echo "■ 현황" >> $__RESULT__;

# DB 접근 사용자가 2명 이상인 경우에만 해당되는 항목
# 같은 DB를 2명 이상이 사용하는데 계정이 사용자 수에 비해 적을 경우 취약
$__MYCONN__ --skip-column-names -B -e "SELECT CONCAT('DB-13', ',', (IF (COUNT(T.DB) > 0, 'X', 'O')), ',,') AS '' FROM (SELECT db, COUNT(user) userCnt FROM mysql.db WHERE 'Y' IN (Select_priv, Insert_priv, Update_priv, Delete_priv, Create_priv, Drop_priv, Grant_priv, References_priv, Index_priv, Alter_priv, Create_tmp_table_priv, Lock_tables_priv, Create_view_priv, Show_view_priv, Create_routine_priv, Alter_routine_priv, Execute_priv, Event_priv, Trigger_priv) GROUP BY db) T WHERE T.userCnt > 1" >> $__RESULT__;
$__MYCONN__ --skip-column-names -B -e "SELECT CASE WHEN ((SELECT COUNT(T.db) FROM (SELECT db, COUNT(user) userCnt FROM mysql.db WHERE 'Y' IN (Select_priv, Insert_priv, Update_priv, Delete_priv, Create_priv, Drop_priv, Grant_priv, References_priv, Index_priv, Alter_priv, Create_tmp_table_priv, Lock_tables_priv, Create_view_priv, Show_view_priv, Create_routine_priv, Alter_routine_priv, Execute_priv, Event_priv, Trigger_priv) GROUP BY db) T WHERE T.userCnt > 1) > 0) \
  THEN '2명 이상의 접근 가능 사용자가 할당된 데이터베이스가 발견되었음' \
  ELSE '2명 이상의 접근 가능 사용자가 할당된 데이터베이스가 발견되지 않았음' END AS '';" >> $__RESULT__;
$__MYCONN__ -B -e "SELECT db, user FROM mysql.db WHERE 'Y' IN (Select_priv, Insert_priv, Update_priv, Delete_priv, Create_priv, Drop_priv, Grant_priv, References_priv, Index_priv, Alter_priv, Create_tmp_table_priv, Lock_tables_priv, Create_view_priv, Show_view_priv, Create_routine_priv, Alter_routine_priv, Execute_priv, Event_priv, Trigger_priv);" >> $__RESULT__;
echo '' >> $__RESULT__;


echo "■ DB-05. 원격에서 DB 서버로의 접속 제한" >> $__RESULT__;
echo "■ 기준 : 허용된 IP 및 포트에 대한 접근 통제가 되어 있는 경우 양호" >> $__RESULT__;
echo "■ 현황" >> $__RESULT__;

$__MYCONN__ --skip-column-names -B -e "SELECT CONCAT('DB-05', ',', (IF (COUNT(host) > 0, 'X', 'O')), ',,') AS '' FROM mysql.user WHERE host='%' AND user <> '';" >> $__RESULT__;
$__MYCONN__ --skip-column-names -B -e "SELECT CASE WHEN((SELECT COUNT(DISTINCT user) FROM mysql.user WHERE host='%' AND user <> '') > 0) \
  THEN '외부 접근이 허용된 계정이 존재함' \
  ELSE '외부 접근이 허용된 계정이 발견되지 않았음' END AS '';" >> $__RESULT__;
$__MYCONN__ -B -e "SELECT DISTINCT host, user FROM mysql.user WHERE user <> '';" >> $__RESULT__;
echo '' >> $__RESULT__;


echo "■ DB-06. DBA이외의 인가되지 않은 사용자 시스템 테이블 접근 제한 설정" >> $__RESULT__;
echo "■ 기준 : DBA만 접근 가능한 테이블에 일반 사용자 접근이 불가능 할 경우 양호" >> $__RESULT__;
echo "■ 현황" >> $__RESULT__;

$__MYCONN__ --skip-column-names -B -e "SELECT CONCAT('DB-06', ',', (IF (COUNT(T.Count) > 0, 'X', 'O')), ',,') AS '' FROM (SELECT db, COUNT(*) Count FROM mysql.db WHERE 'Y' IN (Select_priv, Insert_priv, Update_priv, Delete_priv, Create_priv, Drop_priv, Grant_priv, References_priv, Index_priv, Alter_priv, Create_tmp_table_priv, Lock_tables_priv, Create_view_priv, Show_view_priv, Create_routine_priv, Alter_routine_priv, Execute_priv, Event_priv, Trigger_priv) GROUP BY db) T WHERE T.db = 'mysql'" >> $__RESULT__;
$__MYCONN__ --skip-column-names -B -e "SELECT CASE WHEN ((SELECT COUNT(user) FROM mysql.db WHERE 'Y' IN (Select_priv, Insert_priv, Update_priv, Delete_priv, Create_priv, Drop_priv, Grant_priv, References_priv, Index_priv, Alter_priv, Create_tmp_table_priv, Lock_tables_priv, Create_view_priv, Show_view_priv, Create_routine_priv, Alter_routine_priv, Execute_priv, Event_priv, Trigger_priv) AND db = 'mysql') > 0) \
   THEN 'mysql 데이터베이스의 접근 또는 관리권한이 부여된 계정이 존재함' \
   ELSE 'mysql 데이터베이스의 접근 또는 관리권한이 부여된 계정이 발견되지 않음' END AS '';" >> $__RESULT__;
$__MYCONN__ -B -e "SELECT * FROM mysql.db WHERE 'Y' IN (Select_priv, Insert_priv, Update_priv, Delete_priv, Create_priv, Drop_priv, Grant_priv, References_priv, Index_priv, Alter_priv, Create_tmp_table_priv, Lock_tables_priv, Create_view_priv, Show_view_priv, Create_routine_priv, Alter_routine_priv, Execute_priv, Event_priv, Trigger_priv) AND db = 'mysql';" >> $__RESULT__;
echo '' >> $__RESULT__;


echo "■ DB-07. 오라클 데이터베이스의 경우 리스너 패스워드 설정" >> $__RESULT__;
echo "■ 기준 : Listener의 패스워드가 설정되어 있는 경우 양호" >> $__RESULT__;
echo "■ 현황" >> $__RESULT__;

echo "DB-07,N/A,," >> $__RESULT__;
echo "Oracle 환경에 대한 설정부분으로 해당사항 없음" >> $__RESULT__;
echo '' >> $__RESULT__;


echo "■ DB-14. 불필요한 ODBC/OLE-DB 데이터 소스와 드라이브 제거" >> $__RESULT__;
echo "■ 기준 : 불필요한 ODBC/OLE-DB가 설치되지 않은 경우 양호" >> $__RESULT__;
echo "■ 현황" >> $__RESULT__;

echo "DB-14,N/A,," >> $__RESULT__;
echo "Windows 에서 ODBC/OLE-DB 확인부분으로 해당사항 없음" >> $__RESULT__;
echo '' >> $__RESULT__;


echo "■ DB-15. 일정 횟수의 로그인 실패 시 잠금 정책 설정" >> $__RESULT__;
echo "■ 기준 : 로그인 시도 횟수를 제한하는 값을 설정한 경우 양호" >> $__RESULT__;
echo "■ 현황" >> $__RESULT__;

echo "DB-15,N/A,," >> $__RESULT__;
echo "MySQL 에서 기능을 제공하지 않고 있으며, Oracle 환경에 해당하므로 해당사항 없음" >> $__RESULT__;
echo '' >> $__RESULT__;


echo "■ DB-16. 데이터베이스의 주요 파일 보호 등을 위해 DB 계정의 umask를 022 이상으로 설정"    >> $__RESULT__;
echo "■ 기준 : 계정의 umask가 022 이상으로 설정되어 있는 경우 양호" >> $__RESULT__;
echo "■ 현황" >> $__RESULT__;

if [[ "$(umask | grep '^[0-7][0-7][2-7][2-7]$')" != "" ]]; then
  echo "DB-16,O,," >> $__RESULT__;
  echo "UMASK 가 022 이상으로 설정이 되어 있음 - 현재 설정 값 : $(umask)" >> $__RESULT__;
else
  echo "DB-16,X,," >> $__RESULT__;
  echo "UMASK 가 설정이 되어 있지 않거나 022 보다 낮은 권한으로 설정되어 있음 - 현재 설정 값 : $(umask)" >> $__RESULT__;
fi
echo '' >> $__RESULT__;


echo "■ DB-17. 데이터베이스의 주요 설정파일, 패스워드 파일 등 주요 파일들의 접근 권한 설정" >> $__RESULT__;
echo "■ 기준 : 주요 설정 파일 및 디렉터리의 퍼미션 설정이 되어있는 경우 양호" >> $__RESULT__;
echo "■ 현황" >> $__RESULT__;

if [[ $(find / -type f -name my*.cnf -exec ls -l {} \; | wc -l)-$(find / -type f -name my*.cnf -exec ls -l {} \; | grep -i -e '^-\(rw-\|r--\)[-r]-----' | wc -l) -eq 0 ]]; then
  echo "DB-17,O,," >> $__RESULT__;
  echo "설정 파일(my*.cnf)의 권한이 600 또는 640 미만으로 설정되어 있음(적절한 권한 부여)" >> $__RESULT__;
else
  echo "DB-17,X,," >> $__RESULT__;
  echo "설정 파일(my*.cnf)의 권한이 600 또는 640 이상으로 설정되어 있음(과도한 권한 부여)" >> $__RESULT__;
fi

find / -type f -name my*.cnf -exec ls -l {} \; >> $__RESULT__;

echo '' >> $__RESULT__;


echo "■ DB-18. 관리자 이외의 사용자가 오라클 리스너의 접속을 통해 리스너 로그 및 trace 파일에 대한 변경 권한 제한" >> $__RESULT__;
echo "■ 기준 : 주요 설정 파일 및 로그 파일에 대한 퍼미션을 관리자로 설정한 경우 양호" >> $__RESULT__;
echo "■ 현황" >> $__RESULT__;

echo "DB-18,N/A,," >> $__RESULT__;
echo "Oracle 환경에 대한 설정부분으로 해당사항 없음" >> $__RESULT__;
echo '' >> $__RESULT__;


echo "■ DB-08. 응용프로그램 또는 DBA 계정의 Role이 Public으로 설정되지 않도록 조정" >> $__RESULT__;
echo "■ 기준 : DBA 계정의 Role이 Public으로 설정되어 있지 않은 경우 양호" >> $__RESULT__;
echo "■ 현황" >> $__RESULT__;

echo "DB-08,N/A,," >> $__RESULT__;
echo "Oracle 및 MSSQL 환경에 대한 설정부분으로 해당사항 없음" >> $__RESULT__;
echo '' >> $__RESULT__;


echo "■ DB-09. OS_ROLES, REMOTE_OS_AUTHENTICATION, REMOTE_OS_ROLES를 FALSE로 설정" >> $__RESULT__;
echo "■ 기준 : OS_ROLES, REMOTE_OS_AUTHENTICATION, REMOTE_OS_ROLES설정이 FALSE로 되어있는 경우 양호" >> $__RESULT__;
echo "■ 현황" >> $__RESULT__;

echo "DB-09,N/A,," >> $__RESULT__;
echo "Oracle 환경에 대한 설정부분으로 해당사항 없음" >> $__RESULT__;
echo '' >> $__RESULT__;


echo "■ DB-19. 패스워드 확인함수가 설정되어 적용되는가?" >> $__RESULT__;
echo "■ 기준 : 패스워드 검증 함수로 검증이 진행되는 경우 양호" >> $__RESULT__;
echo "■ 현황" >> $__RESULT__;

echo "DB-19,N/A,," >> $__RESULT__;
echo "Oracle 환경에 대한 설정부분으로 해당사항 없음" >> $__RESULT__;
echo '' >> $__RESULT__;


echo "■ DB-20. 인가되지 않은 Object Owner가 존재하지 않는가?" >> $__RESULT__;
echo "■ 기준 : Object Owner 의 권한이 SYS, SYSTEM, 관리자 계정 등으로 제한된 경우 양호" >> $__RESULT__;
echo "■ 현황" >> $__RESULT__;

echo "DB-20,N/A,," >> $__RESULT__;
echo "Oracle 환경에 대한 설정부분으로 해당사항 없음" >> $__RESULT__;
echo '' >> $__RESULT__;


echo "■ DB-21. grant option이 role에 의해 부여되도록 설정" >> $__RESULT__;
echo "■ 기준 : WITH_GRANT_OPTION이 ROLE에 의하여 설정되어있는 경우 양호" >> $__RESULT__;
echo "■ 현황" >> $__RESULT__;

echo "DB-21,N/A,," >> $__RESULT__;
echo "Oracle 환경에 대한 설정부분으로 해당사항 없음" >> $__RESULT__;
echo '' >> $__RESULT__;


echo "■ DB-22. 데이터베이스의 자원 제한 기능을 TRUE로 설정" >> $__RESULT__;
echo "■ 기준 : RESOURCE_LIMIT 설정이 TRUE로 되어있는 경우 양호" >> $__RESULT__;
echo "■ 현황" >> $__RESULT__;

echo "DB-22,N/A,," >> $__RESULT__;
echo "Oracle 환경에 대한 설정부분으로 해당사항 없음" >> $__RESULT__;
echo '' >> $__RESULT__;


echo "■ DB-10. 데이터베이스에 대해 최신 보안 패치와 밴더 권고사항을 모두 적용" >> $__RESULT__;
echo "■ 기준 : 버전 별 최신 패치를 적용한 경우 양호" >> $__RESULT__;
echo "■ 현황" >> $__RESULT__;

DOT1VERSION=$($__MYCONN__ --skip-column-names -B -e "SELECT SUBSTRING_INDEX(Version(), '.', 2)");

DB23_EXPIRE=0;
if [ "$DOT1VERSION" = "5.5" ]; then
  __LATESTVER__=$__55LAT__;
elif [ "$DOT1VERSION" = "5.6" ]; then
  __LATESTVER__=$__56LAT__;
elif [ "$DOT1VERSION" = "5.7" ]; then
  __LATESTVER__=$__57LAT__;
elif [ "$DOT1VERSION" = "8.0" ]; then
  __LATESTVER__=$__58LAT__;
else
  DB23_EXPIRE=1;
fi

__ISLATEST__=0;
__ISLATEST__=$($__MYCONN__ --skip-column-names -B -e "SELECT SUBSTRING_INDEX(Version(), '-', 1) >= '$__LATESTVER__'");
if [ $__ISLATEST__ -eq 1 ]; then
  echo "DB-10,O,," >> $__RESULT__;
  echo "데이터베이스가 '$__DBVER__' 버전으로 진단기준인 '$__LATESTVER__'과 같거나 높음" >> $__RESULT__;
else
  echo "DB-10,X,," >> $__RESULT__;
  echo "데이터베이스가 '$__DBVER__' 버전으로 진단기준인 '$__LATESTVER__'보다 낮음" >> $__RESULT__;
fi;
echo '' >> $__RESULT__;


echo "■ DB-11. 데이터베이스의 접근, 변경, 삭제 등의 감사기록이 기관의 감사기록 정책에 적합하도록 설정" >> $__RESULT__;
echo "■ 기준 : DBMS의 감사 로그 저장 정책이 수립되어 있으며, 정책이 적용되어 있는 경우 양호" >> $__RESULT__;
echo "■ 현황" >> $__RESULT__;

echo "DB-11,N/A,," >> $__RESULT__;
echo "Oracle 및 MSSQL 환경에 대한 설정부분으로 해당사항 없음" >> $__RESULT__;
echo '' >> $__RESULT__;


echo "■ DB-23. 보안에 취약하지 않은 버전의 데이터베이스를 사용하고 있는가?" >> $__RESULT__;
echo "■ 기준 : Oracle 보안 패치가 지원되는 버전을 사용하는 경우 양호" >> $__RESULT__;
echo "■ 현황" >> $__RESULT__;

if [ $DB23_EXPIRE -eq 0 ]; then
  echo "DB-23,O,," >> $__RESULT__;
  echo "현재 사용하고 있는 데이터베이스는 최신 업데이트를 지원하는 버전임" >> $__RESULT__;
else
  echo "DB-23,X,," >> $__RESULT__;
  echo "현재 사용하고 있는 데이터베이스는 최신 업데이트를 지원하지 않음" >> $__RESULT__;
fi

echo "데이터베이스 버전 : $DOT1VERSION" >> $__RESULT__;
echo '' >> $__RESULT__;


echo "■ DB-24. Audit Table은 데이터베이스 관리자 계정에 속해 있도록 설정" >> $__RESULT__;
echo "■ 기준 : Audit Table 접근 권한이 관리자 계정으로 설정한 경우 양호" >> $__RESULT__;
echo "■ 현황" >> $__RESULT__;

echo "DB-24,N/A,," >> $__RESULT__;
echo "Oracle 환경에 대한 설정부분으로 해당사항 없음" >> $__RESULT__;
echo '' >> $__RESULT__;

echo "------------------------Basic RAW---------------------------" >> $__RESULT__;

echo "기본 정보" >> $__RESULT__;
echo "MySQL Current Version : $__DBVER__" >> $__RESULT__;
echo "Host : $__HOST__" >> $__RESULT__;
echo "Port : $__PORT__" >> $__RESULT__;

echo ''
echo ''
echo "Please Return your $__RESULT__"
echo ''
