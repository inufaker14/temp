#!/bin/bash
LANG=C
export LANG
echo "############# Start Apache Check Script ###############"

# 구분선 함수
# $1 : 파일명
function DividingLine() {
	echo "------------------------------------------------------------------------------" >> $1 2>&1
}

#파일 검사 시간이 지연(10분 이상)되는 시스템을 위한 파일 검사를 인터뷰로 대체하기 위한 변수
# 0 : 파일 검사 진행
# 1 : 파일 검사 패스(인터뷰)
filecheck_pass=0

os=`uname`

_HOSTNAME=`hostname`
Apache_Result=${_HOSTNAME}_apache_result.txt
rm -f $Apache_Result

home=${home:-unknown}
base=${base:-$home}

# Apache 설치 경로
echo "Enter Apache installed Directory(ex. /etc/httpd)"
while true
do
  echo -n "    (default: $home [Enter]) : "
  read apache_root
  if [ "$apache_root" ]; then
    if [ -d "$apache_root" ]; then
      break
    else
      echo "Re-enter Apache installed Directory"
      echo ''
    fi
  else
    echo "Wrong input. Please Re-enter Apache installed Directory"
    echo ''
  fi
done
echo ''

conf="$apache_root/conf/httpd.conf"

echo ''

# Apache httpd.conf 파일 경로
if [ -f "$conf" ]; then
  echo "Apache config file : $apache_root"
else
  echo "  Enter the config file path"
  while true
  do
    echo -n "    (ex. /etc/httpd/conf/httpd.conf) : "
    read conf
    if [ "$conf" ]; then
      if [ -f "$conf" ]; then
        break
      else
        echo "   Not found: httpd.conf, Try Again."
        echo ''
      fi
    else
      echo "   Wrong Path, Try Again."
      echo ''
    fi
  done
fi

echo ''
logs=''

yn="y"

# Apache logs 경로
if [ -d "$logs" ]; then
  echo "Apache logs directory : $apache_root/logs"
else
  echo "  Enter the logs directory path"

  while true
  do
    echo -n '    (ex. /var/log/httpd) : '
    read logs
    if [ "$logs" ]; then
      if [ -d "$logs" ]; then
        break
      else
        echo "   Entered path does not exist. Please try again."
        echo ''

        echo -n "logs directory exist(y/n) : "

        read yn
        if [ "$yn" = "n" ]; then
          break
        fi
      fi
    else
      echo "   Wrong path. Please try again."
      echo ''
    fi
  done
fi
echo ''

# apache conf 파일 목록 얻기
apache_conf_list=(`find $apache_root -type f -name *.conf`)

echo '■ WA-01. 데몬 관리'
echo '■ WA-01. 데몬 관리' >> $Apache_Result
echo '■ 기준: 하위 프로세스가 root가 아닌 nobody로 되어 있을 경우 → Y ' >> $Apache_Result
echo '■ 기준: 하위 프로세스중 root 권한이 부여되어 있을 경우 → N ' >> $Apache_Result
echo '■ 현황' >> $Apache_Result

# PPID 1(root)를 제외하고 grep을 제외하고 root가 있는지 확인 필요

# httpd 데몬 목록에서 PPID가 1을 제외한 데몬이 있는지 확인
WA_01_TXT='WA_01.txt'
WA_01_CHECK_COUNT=0
ps -ef | grep httpd | grep -v "grep" | awk '{print $1"_"$3}' > $WA_01_TXT
for check_01 in `cat $WA_01_TXT`; do
  if [ `echo $check_01 | awk -F_ '{print $2}'` -ne 1 ]; then
    WA_01_CHECK_COUNT=$((WA_01_CHECK_COUNT+1))
  fi
done

if [ $WA_01_CHECK_COUNT -gt 0 ]; then
  echo 'WA-01,O,,' >> $Apache_Result
  echo "Apache 데몬이 Root 권한으로 실행되고 있지 않아 양호함"	>> $Apache_Result;
else
  echo 'WA-01,X,,' >> $Apache_Result
  echo "Apache 데몬이 Root 권한으로 실행되고 있어 취약함"		>> $Apache_Result
  ps -ef | grep httpd >> $Apache_Result
fi

rm -f $WA_01_TXT

echo '[DONE]'
echo '' >> $Apache_Result


echo '■ WA-02. 관리서버 디렉터리 권한 설정'
echo '■ WA-02. 관리서버 디렉터리 권한 설정' >> $Apache_Result
echo "■ 기준: 전용 Web Server 계정 소유, 750(rwxr-x---) 이하 권한인 경우 양호" >> $Apache_Result;
echo "■ 기준: 전용 Web Server 계정 소유가 아니거나 750(rwxr-x---) 초과 권한인 경우 취약" >> $Apache_Result;
echo '■ 현황' >> $Apache_Result

WA_02_TXT='WA_02.txt'
WA_02_CHECK_COUNT=0

# apache 디렉터리 및 하위 디렉터리의 권한 확인
for chk_WA_02 in `find $apache_root -type d`; do
  #echo $chk_WA_02

  # 디렉터리의 권한이 750보다 높으면 파일에 쓰기
  if [ `ls -dl $chk_WA_02 | grep "^.....-.---" | wc -l` -eq 0 ]; then
    ls -dl $chk_WA_02  >> $WA_02_TXT
    WA_02_CHECK_COUNT=$((WA_02_CHECK_COUNT+1))
  fi
done

if [ $WA_02_CHECK_COUNT -gt 0 ]; then
  echo 'WA-02,X,,' >> $Apache_Result
  echo "전용 Web Server 권한이 750(rwxr-x---)보다 높아 취약함"	>> $Apache_Result;

  echo '' >> $Apache_Result
  cat $WA_02_TXT >> $Apache_Result
else
  echo 'WA-02,O,,' >> $Apache_Result
  echo "전용 Web Server 계정 소유이고, 권한이 750(rwxr-x---) 이하 권한으로 양호함"	>> $Apache_Result
fi

rm -f $WA_02_TXT

echo '[DONE]'
echo '' >> $Apache_Result


echo '■ WA-03. 설정파일 권한 설정'
echo '■ WA-03. 설정파일 권한 설정' >> $Apache_Result
echo "■ 기준: 전용 Web Server 계정 소유, 600(rw-------) 또는 700(rwx------) 이하 권한인 경우 양호" >> $Apache_Result;
echo "■ 기준: 전용 Web Server 계정 소유가 아니거나, 600(rw-------) 또는 700(rwx------) 초과 권한인 경우 취약" >> $Apache_Result;
echo '■ 현황' >> $Apache_Result

WA_03_TXT='WA_03.txt'
WA_03_CHECK_COUNT=0

for chk_WA_03 in "${apache_conf_list[@]}"; do
  #echo $chk_WA_03

  # conf 파일의 권한 확인 후 일치하지 않으면 파일에 추가
  if [ `ls -l $chk_WA_03 | grep "^....------" | wc -l` -eq 0 ]; then
    ls -l $chk_WA_03  >> $WA_03_TXT
    WA_03_CHECK_COUNT=$((WA_03_CHECK_COUNT+1))
  fi
done

if [ $WA_03_CHECK_COUNT -gt 0 ]; then
  echo 'WA-03,X,,' >> $Apache_Result
  echo "전용 Web Server 계정 소유가 아니거나 600(rw-------) 또는 700(rwx------) 초과 권한으로 취약함" >> $Apache_Result;

  echo '' >> $Apache_Result
  cat $WA_03_TXT >> $Apache_Result
else
  echo 'WA-03,O,,' >> $Apache_Result
  echo "전용 Web Server 계정 소유, 600(rw-------) 또는 700(rwx------) 이하 권한으로 양호함" >> $Apache_Result;
fi

rm -f $WA_03_TXT

echo '[DONE]'
echo '' >> $Apache_Result


echo '■ WA-04. 디렉터리 검색 기능 제거'
echo '■ WA-04. 디렉터리 검색 기능 제거' >> $Apache_Result
echo '■ 기준: httpd.conf 파일에서 설정된 모든 디렉터리에 Indexes 옵션이 삭제되어 있거나 IncludesNoExec옵션 또는 -Indexes 옵션이 존재할 경우 → Y' >> $Apache_Result
echo '■ 기준: httpd.conf 파일에IncludesNoExec옵션 또는 -Indexes 옵션이 지정되어 있지 않을 경우 → N' >> $Apache_Result
echo '■ 현황' >> $Apache_Result

WA_04_TXT='WA_04.txt'
WA_04_CHECK_COUNT=0

if [ $filecheck_pass -eq 0 ]; then
  # apache의 conf 파일 조회
  for chk_WA_04 in "${apache_conf_list[@]}"; do
    #echo $chk_WA_04

    # conf 파일의 FollowSymLinks를 검색
    chkdata_WA_04=`cat $chk_WA_04 | egrep -i "<Directory |Indexes|</Directory" | grep -v '\#'`

    if [ `echo $chkdata_WA_04 | egrep -i "Indexes" | wc -l` -gt 0 ]; then
      #echo 'File name = '$chk_WA_04
      #echo $chkdata_WA_04

      echo 'File name = '$chk_WA_04 >> $WA_04_TXT
      echo "$chkdata_WA_04" >> $WA_04_TXT
      echo '' >> $WA_04_TXT
      WA_04_CHECK_COUNT=$((WA_04_CHECK_COUNT+1))
    fi
  done

  if [ $WA_04_CHECK_COUNT -gt 0 ]; then
    echo 'WA-04,X,,' >> $Apache_Result
  	echo "디렉터리 검색 기능을 사용해 취약함" >> $Apache_Result;

    echo '' >> $Apache_Result
    cat $WA_04_TXT >> $Apache_Result
  else
    echo 'WA-04,O,,' >> $Apache_Result
  	echo "디렉터리 검색 기능을 사용하지 않아 양호함" >> $Apache_Result;
  fi

  rm -f $WA_04_TXT
else
  echo 'WA-04,C,,' >> $Apache_Result
  echo '[수동진단] 담당자 인터뷰 필요-파일 검사 시간 지연(10분 이상)' >> $Apache_Result
fi

echo '[DONE]'
echo '' >> $Apache_Result


echo '■ WA-05. 로그 디렉터리/파일 권한 설정'
echo '■ WA-05. 로그 디렉터리/파일 권한 설정' >> $Apache_Result
echo "■ 기준: 디렉터리의 경우 전용계정 소유자 및 750(drwxr-x---) 이하 권한인 경우 양호" >> $Apache_Result;
echo "■ 기준: 로그파일의 경우 전용계정 소유자 및 640(drw-r-----) 이하 권한인 경우 양호" >> $Apache_Result;
echo '■ 현황' >> $Apache_Result

if [ $filecheck_pass -eq 0 ]; then
  WA_05_TXT='WA_05.txt'
  WA_05_CHECK_COUNT=0

  # 로그 디렉터리 권한 확인
  if [ `ls -dl $logs | grep "^.....-.---" | wc -l` -eq 0 ]; then
    ls -l $logs  >> $WA_05_TXT
    WA_05_CHECK_COUNT=$((WA_05_CHECK_COUNT+1))
  fi

  # apache의 로그 파일 조회
  for chk_WA_05 in `find $logs -type f -name *.log`; do
    #echo $chk_WA_05

    # conf 파일의 권한 확인 후 일치하지 않으면 파일에 추가
    if [ `ls -l $chk_WA_05 | grep "^...-.-----" | wc -l` -eq 0 ]; then
      ls -l $chk_WA_05  >> $WA_05_TXT
      WA_05_CHECK_COUNT=$((WA_05_CHECK_COUNT+1))
    fi
  done

  if [ $WA_05_CHECK_COUNT -gt 0 ]; then
    echo 'WA-05,X,,' >> $Apache_Result
    echo "로그 디렉터리(750:drwxr-x---) 또는 로그 파일(640:-rw-r-----)의 권한이 기준 초과해 취약함" >> $Apache_Result;

    echo '' >> $Apache_Result
    cat $WA_05_TXT >> $Apache_Result
  else
    echo 'WA-05,O,,' >> $Apache_Result
    echo "로그 디렉터리 또는 로그 파일의 권한이 기준 이하로 양호함" >> $Apache_Result;
  fi

  rm -f $WA_05_TXT
else
  echo 'WA-05,C,,' >> $Apache_Result
  echo '[수동진단] 담당자 인터뷰 필요-파일 검사 시간 지연(10분 이상)' >> $Apache_Result
fi

echo '[DONE]'
echo '' >> $Apache_Result


echo '■ WA-06. 에러 메시지 관리'
echo '■ WA-06. 에러 메시지 관리' >> $Apache_Result
echo '■ 기준: httpd.conf 파일에서 시스템의 정보를 노출하지 않는 별도의 에러메시지로 연결되어 있을 경우 → Y ' >> $Apache_Result
echo '■ 기준: 400, 401, 403, 404, 500 페이지 중 하나라도 누락되어 있을 경우 → N ' >> $Apache_Result
echo '■ 현황' >> $Apache_Result

WA_06_TXT='WA_06.txt'
WA_06_CHECK_COUNT=0

# conf 파일의 에러페이지 설정 검색
chkdata_WA_06=`cat "$conf" | egrep -i "ErrorDocument|400|401|403|404|500" | grep -v '\#'`
#echo 'File name = '$chk_WA_06
#echo "$chkdata_WA_06"

# 결과값의 문자열 길이 얻기
chkdatalen_WA_06=${#chkdata_WA_06}

# 문자열 길이가 0보다 크면 파일에 쓰기
if [ $chkdatalen_WA_06 -gt 0 ]; then
  echo 'File name = '$conf >> $WA_06_TXT
  echo "$chkdata_WA_06" >> $WA_06_TXT

  WA_06_CHECK_COUNT=$((WA_06_CHECK_COUNT+1))
fi

if [ $WA_06_CHECK_COUNT -eq 0 ]; then
  echo 'WA-06,X,,' >> $Apache_Result
  echo "에러 페이지(400, 401, 403, 404, 500) 설정이 없어 취약함" >> $Apache_Result;
else
  echo 'WA-06,C,,' >> $Apache_Result
  echo "[수동진단] 에러 페이지(400, 401, 403, 404, 500) 설정 확인 필요" >> $Apache_Result;

  echo '' >> $Apache_Result
  cat $WA_06_TXT >> $Apache_Result
fi

rm -f $WA_06_TXT

echo '[DONE]'
echo '' >> $Apache_Result


echo '■ WA-07. 헤더 정보 노출 방지'
echo '■ WA-07. 헤더 정보 노출 방지' >> $Apache_Result
echo '■ 기준: httpd.conf 파일에서 ServerTockens 설정을 확인' >> $Apache_Result
echo '■ 기준: ServerTokens설정이 Prod로 설정 → Y' >> $Apache_Result
echo '■ 기준: ServerTokens설정이 Prod로 설정되어 있지 않음 → N' >> $Apache_Result
echo '■ 현황' >> $Apache_Result

WA_07_TXT='WA_07.txt'
WA_07_CHECK_COUNT=0

chkdata_WA_07=`cat $conf | grep -iEHn "^\s*ServerTokens|^\s*ServerSignature"`

# 결과값의 문자열 길이 얻기
chkdatalen_WA_07=${#chkdata_WA_07}
#echo "$chkdatalen_WA_07"

#echo "$chkdata_WA_07"
#echo "$chkdata_WA_07" | wc -l

# 문자열 길이가 0보다 크면 파일에 쓰기
if [ $chkdatalen_WA_07 -gt 0 ]; then
  #echo $chk_WA_07
  echo 'File name = '$conf >> $WA_07_TXT
  echo "$chkdata_WA_07" >> $WA_07_TXT

  WA_07_CHECK_COUNT=$((WA_07_CHECK_COUNT+1))
fi

if [ `cat $WA_07_TXT | grep -i "ServerTokens" | grep -i "Prod" | wc -l` -eq 0 ]; then
  echo 'WA-07,X,,' >> $Apache_Result
  echo "ServerTokens이 Prod로 설정되지 않아 취약함"	>> $Apache_Result;

  echo '' >> $Apache_Result
  cat $WA_07_TXT >> $Apache_Result
else
  if [ `cat $WA_07_TXT | grep -i "ServerSignature" | grep -i "Off" | wc -l` -eq 0 ]; then
    echo 'WA-07,X,,' >> $Apache_Result
    echo "ServerTokens이 Prod이고 ServerSignature가 Off로 설정되지 않아 취약함" >> $Apache_Result;

    echo '' >> $Apache_Result
    cat $WA_07_TXT >> $Apache_Result
  else
    echo 'WA-07,C,,' >> $Apache_Result
    echo "ServerTokens이 Prod이고 ServerSignature 가 Off로 설정됨"	>> $Apache_Result;

    echo '' >> $Apache_Result
    cat $WA_07_TXT >> $Apache_Result
  fi
fi

rm -f $WA_07_TXT

echo '[DONE]'
echo '' >> $Apache_Result


echo '■ WA-08. FollowSymLinks 옵션 비활성화'
echo '■ WA-08. FollowSymLinks 옵션 비활성화' >> $Apache_Result
echo '■ 기준: httpd.conf파일에서 설정된 모든 디렉터리에 FollowSymLinks 옵션이 삭제되어 있거나 -FollowSymLinks 옵션으로 설정되어 있을 경우 → Y' >> $Apache_Result
echo '■ 기준: httpd.conf파일에서 설정된 모든 디렉터리에 FollowSymLinks 옵션이 존재하고 있을 경우 → N' >> $Apache_Result
echo '■ 현황' >> $Apache_Result

WA_08_TXT='WA_08.txt'
WA_08_CHECK_COUNT=0

if [ $filecheck_pass -eq 0 ]; then
  # apache의 conf 파일 조회
  for chk_WA_08 in "${apache_conf_list[@]}"; do
    #echo $chk_WA_08

    # conf 파일의 FollowSymLinks를 검색
    chkdata_WA_08=`cat $chk_WA_08 | egrep -i "<Directory |FollowSymLinks|</Directory" | grep -v '\#'`

    if [ `echo $chkdata_WA_08 | egrep -i "FollowSymLinks" | wc -l` -gt 0 ]; then
      #echo 'File name = '$chk_WA_08
      #echo $chkdata_WA_08

      echo 'File name = '$chk_WA_08 >> $WA_08_TXT
      echo "$chkdata_WA_08" >> $WA_08_TXT
      echo '' >> $WA_08_TXT
      WA_08_CHECK_COUNT=$((WA_08_CHECK_COUNT+1))
    fi
  done

  if [ $WA_08_CHECK_COUNT -gt 0 ]; then
    echo 'WA-08,X,,' >> $Apache_Result
  	echo "Options 지시자에서 심블릭 링크를 가능하게 하는 옵션인 FollowSymLinks가 제거되어 있지 않아 취약함" >> $Apache_Result;

    echo '' >> $Apache_Result
    cat $WA_08_TXT >> $Apache_Result
  else
    echo 'WA-08,O,,' >> $Apache_Result
  	echo "Options 지시자에서 심블릭 링크를 가능하게 하는 옵션인 FollowSymLinks가 제거되어 있어 양호함" >> $Apache_Result;
  fi

  rm -f $WA_08_TXT
else
  echo 'WA-08,C,,' >> $Apache_Result
  echo '[수동진단] 담당자 인터뷰 필요-파일 검사 시간 지연(10분 이상)' >> $Apache_Result
fi

echo '[DONE]'
echo '' >> $Apache_Result


echo '■ WA-09. MultiView 옵션 비활성화'
echo '■ WA-09. MultiView 옵션 비활성화' >> $Apache_Result
echo '■ 기준: httpd.conf파일에서 설정된 모든 디렉터리에 MultiViews 옵션이 삭제되어 있거나 -MultiView 옵션이 존재하고 있을 경우 → Y' >> $Apache_Result
echo '■ 기준: httpd.conf파일에서 설정된 모든 디렉터리에 MultiViews 옵션이 존재하고 있을 경우 → N' >> $Apache_Result
echo '■ 현황' >> $Apache_Result

WA_09_TXT='WA_09.txt'
WA_09_CHECK_COUNT=0

if [ $filecheck_pass -eq 0 ]; then
  # apache의 conf 파일 조회
  for chk_WA_09 in "${apache_conf_list[@]}"; do
    #echo $chk_WA_09

    # conf 파일의 MultiViews를 검색
    chkdata_WA_09=`cat $chk_WA_09 | egrep -i "<Directory |MultiViews|</Directory" | grep -v '\#'`

    if [ `echo $chkdata_WA_09 | egrep -i "MultiViews" | wc -l` -gt 0 ]; then
      echo 'File name = '$chk_WA_09 >> $WA_09_TXT
      echo "$chkdata_WA_09" >> $WA_09_TXT
      echo '' >> $WA_09_TXT
      WA_09_CHECK_COUNT=$((WA_09_CHECK_COUNT+1))
    fi
  done

  if [ $WA_09_CHECK_COUNT -gt 0 ]; then
    echo 'WA-09,X,,' >> $Apache_Result
    echo "MultiViews 옵션이 존재해 취약함" >> $Apache_Result;

    echo '' >> $Apache_Result
    cat $WA_09_TXT >> $Apache_Result
  else
    echo 'WA-09,O,,' >> $Apache_Result
    echo "MultiViews 옵션이 제거되어 있어 양호함" >> $Apache_Result;
  fi

  rm -f $WA_09_TXT
else
  echo 'WA-09,C,,' >> $Apache_Result
  echo '[수동진단] 담당자 인터뷰 필요-파일 검사 시간 지연(10분 이상)' >> $Apache_Result
fi

echo '[DONE]'
echo '' >> $Apache_Result


echo '■ WA-10. HTTP Method 제한'
echo '■ WA-10. HTTP Method 제한' >> $Apache_Result
echo '■ 기준: GET POST OPTIONS 이외의 HTTP 메소드가 제한되어 있는 경우 → Y' >> $Apache_Result
echo '■ 기준: GET POST OPTIONS 이외의 HTTP 메소드가 존재하는 경우 → N' >> $Apache_Result
echo '■ 현황' >> $Apache_Result

# <Limit가 없는 경우에는 메소드 제한이 없음
if [ `cat "$conf" | egrep -i "<Limit|</Limit" | grep -v '\#' | wc -l` -gt 0 ]; then
  echo 'WA-10,C,,' >> $Apache_Result
  echo '[수동진단]' >> $Apache_Result

  echo '' >> $Apache_Result
  echo '--httpd.conf 내용--' >> $Apache_Result
  cat "$conf" | egrep -i "<Directory |<Limit|Order |Allow |Deny |</Limit|</Directory" | grep -v '\#' >> $Apache_Result
else
  echo 'WA-10,X,,' >> $Apache_Result
  echo 'HTTP 메소드 제한되지 않아 취약함' >> $Apache_Result
fi

echo '[DONE]'
echo '' >> $Apache_Result


echo '■ WA-11. 로그 포맷 설정'
echo '■ WA-11. 로그 포맷 설정' >> $Apache_Result
echo '■ 기준: httpd.conf파일에서 CumtomLog 설정 부분이 Combined 포맷으로 설정되어 있는 경우 → Y ' >> $Apache_Result
echo '■ 기준: httpd.conf파일에서 CumtomLog 설정 부분이 Combined 포맷이 아닌 다른 것으로 지정되어 있을 경우(common, referer, agent등) → N ' >> $Apache_Result
echo '■ 현황' >> $Apache_Result

echo 'WA-11,C,,' >> $Apache_Result
echo '[수동진단]' >> $Apache_Result

echo '--httpd.conf 내용--' >> $Apache_Result
cat "$conf" | egrep -i "CustomLog|LogFormat" | grep -v '\#' >> $Apache_Result

echo '[DONE]'
echo '' >> $Apache_Result


echo "WA-12 Check Start..."
echo "■ WA-12. 웹서비스 웹 프로세스 권한 제한" >> $Apache_Result 2>&1
echo "■ 기준: 웹 프로세스 권한을 제한 했을 경우 양호(User root, Group root 가 아닌 경우)"	>> $Apache_Result 2>&1
echo "■ 현황" >> $Apache_Result 2>&1

if [ `ps -ef | grep "httpd" | grep -v "ns-httpd" | grep -v "grep" | awk '{print $8}' | grep "/" | grep -v "httpd.conf" | uniq | wc -l` -gt 0 ]; then
	echo "$ACONF 파일 설정 확인"	>> $Apache_Result 2>&1
	DividingLine $Apache_Result

	if [ `cat $ACONF | grep -i "user" | grep -v "\#" | egrep -v "^LoadModule|LogFormat|IfModule|UserDir" | grep -i "user" | grep -i "root" | wc -l` -gt 0 ]; then
		echo "WA-12,X,,"	>> $Apache_Result 2>&1
		echo "Apache 데몬이 root 권한으로 구동되어 취약함"	>> $Apache_Result 2>&1
	else
		if [ `cat $ACONF | grep -i "user" | grep -v "\#" | egrep -v "^LoadModule|LogFormat|IfModule|UserDir" | grep -i "group" | grep -i "root" | wc -l` -gt 0 ]; then
			echo "WA-12,X,,"	>> $Apache_Result 2>&1
			echo "Apache 데몬이 root 권한으로 구동되어 취약함"	>> $Apache_Result 2>&1
		else
			echo "WA-12,O,,"	>> $Apache_Result 2>&1
			echo "Apache 데몬이 root 권한으로 구동되지 않아 양호함"	>> $Apache_Result 2>&1
		fi

		NewLine $Apache_Result

		cat $ACONF | grep -i "group" | grep -v "\#" | egrep -v "^LoadModule|LogFormat|IfModule|UserDir" | grep -i "group" >> $Apache_Result 2>&1
	fi

	cat $ACONF | grep -i "user" | grep -v "\#" | egrep -v "^LoadModule|LogFormat|IfModule|UserDir" | grep -i "user" >> $Apache_Result 2>&1

	NewLine $Apache_Result
	echo "httpd 데몬 동작 계정 확인"	>> $Apache_Result 2>&1
	DividingLine $Apache_Result

	ps -ef | grep "httpd"	>> $Apache_Result 2>&1
else
	echo "WA-12,O,,"	>> $Apache_Result 2>&1
	echo "Apache 서비스를 사용하지 않아 양호함"	>> $Apache_Result 2>&1
fi

NewLine $Apache_Result


echo "WA-13 Check Start..."
echo "■ WA-13. 웹서비스 상위 디렉터리 접근 금지" >> $Apache_Result 2>&1
echo "■ 기준: httpd.conf 파일의 Directory 부분의 AllowOverride None 설정이 아니면 양호"	>> $Apache_Result 2>&1
echo "■ 현황" >> $Apache_Result 2>&1

if [ `ps -ef | grep "httpd" | grep -v "ns-httpd" | grep -v "grep" | awk '{print $8}' | grep "/" | grep -v "httpd.conf" | uniq | wc -l` -gt 0 ]; then
	echo "$ACONF 파일 설정 확인"	>> $Apache_Result 2>&1
	DividingLine $Apache_Result

	cat $ACONF | egrep -i "DocumentRoot " | grep -v '\#'	>> $Apache_Result 2>&1

	NewLine $Apache_Result

	if [ `cat $ACONF | egrep -i "<Directory |AllowOverride|</Directory" | grep -v '\#' | grep -i "None" | wc -l` -gt 0 ]; then
		echo "WA-13,X,,"	>> $Apache_Result 2>&1
		echo "상위 디렉터리에 이동제한을 설정하지 않아 취약함"	>> $Apache_Result 2>&1
	else
		echo "WA-13,O,,"	>> $Apache_Result 2>&1
		echo "상위 디렉터리에 이동제한을 설정해 양호함"	>> $Apache_Result 2>&1
	fi

	NewLine $Apache_Result

	cat $ACONF | egrep -i "<Directory |AllowOverride|</Directory" | grep -v '\#'	>> $Apache_Result 2>&1
else
	echo "WA-13,O,,"	>> $Apache_Result 2>&1
	echo "Apache 서비스를 사용하지 않아 양호함"	>> $Apache_Result 2>&1
fi

NewLine $Apache_Result


echo "WA-14 Check Start..."
echo "■ WA-14. 웹서비스 파일 업로드 및 다운로드 제한" >> $Apache_Result 2>&1
echo "■ 기준: 시스템에 따라 파일 업로드 및 다운로드에 대한 용량이 제한되어 있는 경우 양호"	>> $Apache_Result 2>&1
echo "  <Directory 경로>의 LimitRequestBody 지시자에 제한용량이 설정되어 있는 경우 양호" >> $Apache_Result 2>&1
echo "■ 현황" >> $Apache_Result 2>&1

if [ `ps -ef | grep "httpd" | grep -v "ns-httpd" | grep -v "grep" | awk '{print $8}' | grep "/" | grep -v "httpd.conf" | uniq | wc -l` -gt 0 ]; then
	echo "$ACONF 파일 설정 확인"	>> $Apache_Result 2>&1
	DividingLine $Apache_Result

	cat $ACONF | egrep -i "DocumentRoot " | grep -v '\#'	>> $Apache_Result 2>&1

	NewLine $Apache_Result
	if [ `cat $ACONF | egrep -i "<Directory |LimitRequestBody|</Directory" | grep -v '\#' | wc -l` -eq 0 ]; then
		echo "WA-14,X,,"	>> $Apache_Result 2>&1
		echo "파일 업로드 및 다운로드에 대한 용량이 제한되어 있지 않아 취약함"	>> $Apache_Result 2>&1
	else
		echo "WA-14,C,,"	>> $Apache_Result 2>&1
		echo "[수동진단]파일 업로드 및 다운로드에 대한 용량이 제한여부 확인"	>> $Apache_Result 2>&1
	fi

	NewLine $Apache_Result

	cat $ACONF | egrep -i "<Directory |LimitRequestBody|</Directory" | grep -v '\#'	>> $Apache_Result 2>&1
else
	echo "WA-14,O,,"	>> $Apache_Result 2>&1
	echo "Apache 서비스를 사용하지 않아 양호함"	>> $Apache_Result 2>&1
fi

NewLine $Apache_Result


echo "WA-15 Check Start..."
echo "■ WA-15. 웹 서비스 영역의 분리" >> $Apache_Result 2>&1
echo "■ 기준: DocumentRoot를 기본 디렉터리(~/Apache/htdocs)가 아닌 별도의 디렉터리로 지정한 경우 양호"	>> $Apache_Result 2>&1
echo "■ 현황" >> $Apache_Result 2>&1

if [ `ps -ef | grep "httpd" | grep -v "ns-httpd" | grep -v "grep" | awk '{print $8}' | grep "/" | grep -v "httpd.conf" | uniq | wc -l` -gt 0 ]; then
	echo "$ACONF 파일 설정 확인"	>> $Apache_Result 2>&1
	DividingLine $Apache_Result
	if [ `cat $ACONF | egrep -i "DocumentRoot " | grep -v '\#' | grep "/usr/local/apache/htdocs" | wc -l` -gt 0 ]; then
		echo "WA-15,X,,"	>> $Apache_Result 2>&1
		echo "DocumentRoot를 기본 디렉터리로 지정하여 취약함"	>> $Apache_Result 2>&1
	else
		echo "WA-15,O,,"	>> $Apache_Result 2>&1
		echo "DocumentRoot를 별도의 디렉터리로 지정하여 양호함"	>> $Apache_Result 2>&1
	fi

	cat $ACONF | egrep -i "DocumentRoot " | grep -v '\#'	>> $Apache_Result 2>&1

	NewLine $Apache_Result
else
	echo "WA-15,O,,"	>> $Apache_Result 2>&1
	echo "Apache 서비스를 사용하지 않아 양호함"	>> $Apache_Result 2>&1
fi

NewLine $Apache_Result


echo '■ WA-16. 불필요한 manual 디렉터리 삭제'
echo '■ WA-16. 불필요한 manual 디렉터리 삭제' >> $Apache_Result
echo '■ 기준: 사용자 브라우저에서 manual로 접속이 불가능' >> $Apache_Result
echo '■ 기준: apache_root 설치 디렉터리/manual 디렉터리가 존재하지 않음' >> $Apache_Result
echo '■ 기준: /conf/httpd.conf 에서 매뉴얼과 관련된 부분이 삭제 또는 주석 처리' >> $Apache_Result
echo '■ 현황' >> $Apache_Result

# 점검할 디렉터리 목록
listdir_WA_16=(
'/cgi-bin'
'/htdocs/manual'
'/manual'
)

WA_16_TXT='WA_16.txt'
WA_16_CHECK_COUNT=0

# 디렉터리 유무 확인
for chk_WA_16 in "${listdir_WA_16[@]}"; do
  #echo $apache_root$chk_WA_16

  # 디렉터리가 존재하면 파일에 추가
  if [ -d $apache_root$chk_WA_16 ]; then
    $apache_root$chk_WA_16  >> $WA_16_TXT
    WA_16_CHECK_COUNT=$((WA_16_CHECK_COUNT+1))
  fi
done

if [ $WA_16_CHECK_COUNT -gt 0 ]; then
  echo 'WA-16,X,,' >> $Apache_Result
  echo "불필요한 디렉터리가 제거되어 있지 않아 취약함" >> $Apache_Result;

  echo '' >> $Apache_Result
  cat $WA_16_TXT >> $Apache_Result
else
  echo 'WA-16,O,,' >> $Apache_Result
  echo "불필요한 디렉터리가 제거되어 있어 양호함" >> $Apache_Result;
fi

rm -f $WA_16_TXT

echo '[DONE]'
echo '' >> $Apache_Result


echo "WA-17 Check Start..."
echo "■ WA-17. 3. 서비스 관리 > 3.20 웹서비스 불필요한 파일 제거" >> $Apache_Result 2>&1
echo "■ 기준: /htdocs/manual 또는 /apache/manual 디렉터리와,"	>> $Apache_Result 2>&1
echo "       : /cgi-bin/test-cgi, /cgi-bin/printenv 파일이 제거되어 있는 경우 양호"	>> $Apache_Result 2>&1
echo "■ 현황" >> $Apache_Result 2>&1

if [ `ps -ef | grep "httpd" | grep -v "ns-httpd" | grep -v "grep" | awk '{print $8}' | grep "/" | grep -v "httpd.conf" | uniq | wc -l` -gt 0 ]; then
	if [ -d $AHOME/cgi-bin ]; then
		echo "$AHOME/cgi-bin 파일"	>> $Apache_Result 2>&1
		DividingLine $Apache_Result

		ls -ld $AHOME/cgi-bin/test-cgi	>> $Apache_Result 2>&1
		ls -ld $AHOME/cgi-bin/printenv	>> $Apache_Result 2>&1

		NewLine $Apache_Result
		echo "WA-17,X,,"	>> $Apache_Result 2>&1
		echo "$AHOME/cgi-bin 디렉터리가 제거되어 있지 않아 취약함"	>> $Apache_Result 2>&1
	else
		if [ -d $AHOME/htdocs/manual ]; then
			echo "$AHOME/htdocs/manual 파일"	>> $Apache_Result 2>&1
			DividingLine $Apache_Result

			ls -ld $AHOME/htdocs/manual	>> $Apache_Result 2>&1

			NewLine $Apache_Result
			echo "WA-17,X,,"	>> $Apache_Result 2>&1
			echo "$AHOME/htdocs/manual 디렉터리가 제거되어 있지 않아 취약함"	>> $Apache_Result 2>&1
		else
			if [ -d $AHOME/manual ]; then
				echo "$AHOME/manual 파일 설정"	>> $Apache_Result 2>&1
				DividingLine $Apache_Result

				ls -ld $AHOME/manual	>> $Apache_Result 2>&1

				NewLine $Apache_Result
				echo "WA-17,X,,"	>> $Apache_Result 2>&1
				echo "$AHOME/manual 디렉터리가 제거되어 있지 않아 취약함"	>> $Apache_Result 2>&1
			else
				echo "WA-17,O,,"	>> $Apache_Result 2>&1
				echo "매뉴얼 파일 및 디렉터리가 제거되어 있어 양호함"	>> $Apache_Result 2>&1
				NewLine $Apache_Result
			fi
			NewLine $Apache_Result
		fi
		NewLine $Apache_Result
	fi
else
	echo "WA-17,O,,"	>> $Apache_Result 2>&1
	echo "Apache 서비스를 사용하지 않아 양호함"	>> $Apache_Result 2>&1
fi

NewLine $Apache_Result

echo '■ WA-18. 보안 패치 적용'
echo '■ WA-18. 보안 패치 적용' >> $Apache_Result
echo '■ 기준: 마지막 패치가 최근 1년 이내이면 양호' >> $Apache_Result
echo '■ 기준: 1년 이내 패치가 존재하지 않으며 패치에 대한 적용 검토 및 대책이 존재하지 않음' >> $Apache_Result
echo '■ 현황' >> $Apache_Result

echo 'WA-18,C,,' >> $Apache_Result
echo '[수동진단]' >> $Apache_Result

echo '--httpd daemon--' >> $Apache_Result
ps -ef | grep httpd >> $Apache_Result
echo '' >> $Apache_Result

echo '--httpd version--' >> $Apache_Result
httpd -v >> $Apache_Result

echo '[DONE]'
echo '' >> $Apache_Result

echo "------------------------Basic RAW---------------------------" >> $Apache_Result
echo '' >> $Apache_Result
echo "HOSTNAME : `hostname`" >> $Apache_Result
echo "VERSION : " >> $Apache_Result
echo "IP : " >> $Apache_Result

echo '' >> $Apache_Result

echo "------------------------사용자 입력 정보------------------------" >> $Apache_Result
echo '' >> $Apache_Result
echo 'apache root : '$apache_root >> $Apache_Result
echo 'apache conf : '$conf >> $Apache_Result
echo 'apache logs : '$logs >> $Apache_Result

echo '' >> $Apache_Result

echo "------------------------시스템 정보------------------------" >> $Apache_Result
echo '' >> $Apache_Result

echo "--OS Information--" >> $Apache_Result
echo "`uname -a`" >> $Apache_Result
echo '' >> $Apache_Result

echo "--Script End Time--" >> $Apache_Result
echo "`date`" >> $Apache_Result
echo '' >> $Apache_Result

echo "--httpd.conf--" >> $Apache_Result
echo "$conf" >> $Apache_Result
cat "$conf">> $Apache_Result
echo '' >> $Apache_Result
echo "--httpd.conf--" >> $Apache_Result

echo "--Network Information--" >> $Apache_Result
os=`uname`
if [ "%os" = "HP-UX" ]; then
	lanscan -v >> $Apache_Result
else
	ifconfig -a >> $Apache_Result
fi

echo ''
echo ''
echo "Please Return your $Apache_Result"
echo ''
