#!/bin/sh
HOSTNAME=`hostname`
LANG=C
export LANG

#----------------------함수 목록 시작----------------------#
# 개행 지원 함수
# $1 : 파일명
function NewLine() {
	echo "" >> $1 2>&1
}

# 구분선 함수
# $1 : 파일명
function DividingLine() {
	echo "------------------------------------------------------------------------------" >> $1 2>&1
}

# echo로 파일에 텍스트 쓰기 함수
# $1 : 파일명
# $2 : 텍스트
function WriteEcho() {
	echo $2 >> $1 2>&1
}

# 새 파일 생성
# $1 : 파일명
function NewFile() {
	echo "" > $1
}

# 리눅스 버전 확인
function CheckVersion() {
	if grep -q -i "release 5" /etc/redhat-release ; then
		return 5
	elif grep -q -i "release 6" /etc/redhat-release ; then
		return 6
	elif grep -q -i "release 7" /etc/redhat-release ; then
		return 7
	else
		return 0
	fi

	return -1
}

# $OSTYPE으로 OS 종류 확인
function CheckOSTYPE() {
	case "$OSTYPE" in
		solaris*) echo "SOLARIS" ;;
		darwin*)  echo "OSX" ;;
		linux*)   echo "LINUX" ;;
		bsd*)     echo "BSD" ;;
		msys*)    echo "WINDOWS" ;;
		*)        echo "unknown: $OSTYPE" ;;
	esac
}

# uname으로 OS 종류 확인
function CheckOSTYPE_uname() {
	# Detect the platform (similar to $OSTYPE)
	OS="`uname`"
	case $OS in
		'Linux')
			OS='Linux'
			alias ls='ls --color=auto'
			;;

		'FreeBSD')
			OS='FreeBSD'
			alias ls='ls -G'
			;;
		'WindowsNT')
			OS='Windows'
			;;
		'Darwin')
			OS='Mac'
			;;
		'SunOS')
			OS='Solaris'
			;;
		'AIX')
			OS='AIX'
			;;
		*) ;;
	esac
}

# 쉘 종류 확인
# 함수 호출 및 반환값 방법
# variable=`CheckShell`
# 변수=`함수 이름`
function CheckShell() {
	checkSh="`echo $SHELL | awk -F "/" '{print $NF}'`"

	case $checkSh in
		'sh')
			echo 'sh'
			;;
		'csh')
			echo 'csh'
			;;
		'tcsh')
			echo 'tcsh'
			;;
		'ksh')
			echo 'ksh'
			;;
		'bash')
			echo 'bash'
			;;
		*)
			echo 'unknown'
			;;
	esac
}
#----------------------함수 목록 끝----------------------#

#파일 검사 시간이 지연(10분 이상)되는 시스템을 위한 파일 검사를 인터뷰로 대체하기 위한 변수
# 0 : 파일 검사 진행
# 1 : 파일 검사 패스(인터뷰)
filecheck_pass=0

#파일 이름 설정
filepath=$HOSTNAME"_linux_result.txt"

#기존 결과 파일 삭제
rm -f $filepath

#2>&1 : stderr를 stdout으로 리디렉션

echo "U-01 Check Start..."
echo "■ U-01. 1. 계정관리 > 1.1 root 계정 원격 접속 제한" >> $filepath 2>&1
echo "■ 기준: /etc/securetty 파일에 pts/* 설정이 있으면 취약"	>> $filepath 2>&1
echo "■ 기준: /etc/securetty 파일에 pts/* 설정이 없거나 주석처리가 되어 있고, /etc/pam.d/login에서 auth required /lib/security/pam_securetty.so 라인에 주석(#)이 없으면 양호"	>> $filepath 2>&1
echo "■ 현황" >> $filepath 2>&1

#파일에서 pts 중 주석처리가 안된 목록이 있으면 취약
if [ `cat /etc/securetty | grep "pts" | grep -v "^#" | wc -l` -gt 0 ]; then
	echo "U-01,X,,"	>> $filepath 2>&1
	echo "root 계정 원격 접속을 제한하고 있지 않아 취약함" >> $filepath 2>&1
	echo "[설정]" >> $filepath 2>&1
	cat /etc/securetty | grep "pts"	>> $filepath 2>&1
else
	# /etc/pam.d/login 파일 설정에서 pam_securetty.so 설정이 주석인지 확인
	if [ `cat /etc/pam.d/login | grep "pam_securetty.so" | grep "^#" | wc -l` -gt 0 ]; then
		echo "U-01,X,,"	>> $filepath 2>&1
		NewLine $filepath
		echo "root 계정 원격 접속을 제한하고 있지 않아 취약함"	>> $filepath 2>&1
	else
		echo "U-01,O,,"	>> $filepath 2>&1
		echo "root 계정 원격 접속을 제한하고 있어 양호함"	>> $filepath 2>&1
	fi
	echo "[설정]" >> $filepath 2>&1
	cat /etc/pam.d/login | grep "pam_securetty.so"	>> $filepath 2>&1
fi
NewLine $filepath

echo "telnet 서비스 추가 확인 /etc/services 파일에서 포트 확인"	>> $filepath 2>&1
DividingLine $filepath

cat /etc/services | awk -F" " '$1=="telnet" {print $1 "   " $2}' | grep "tcp"	>> $filepath 2>&1

NewLine $filepath
echo "서비스 포트 활성화 여부 확인"	>> $filepath 2>&1
DividingLine $filepath

if [ `cat /etc/services | awk -F" " '$1=="telnet" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]; then
	port=`cat /etc/services | awk -F" " '$1=="telnet" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	if [ `netstat -na | grep ":$port " | grep -i "^tcp" | wc -l` -gt 0 ]; then
		netstat -na | grep ":$port " | grep -i "^tcp"	>> $filepath 2>&1
	else
		echo "Telnet Service Disable"	>> $filepath 2>&1
	fi
fi

NewLine $filepath


echo "U-02 Check Start..."
echo "■ U-02. 1. 계정관리 > 1.2 패스워드 복잡성 설정" >> $filepath 2>&1
echo "■ 기준: 영문/숫자/특수문자가 혼합된 8자리 이상의 패스워드가 설정된 경우 양호"	>> $filepath 2>&1
echo "■ 현황" >> $filepath 2>&1

echo "U-02,C,," >> $filepath 2>&1
echo "[설정]" >> $filepath 2>&1
# if [ -f /etc/shadow ]; then
# 	echo "① /etc/shadow 파일"	>> $filepath 2>&1
# 	DividingLine $filepath
# 	cat /etc/shadow	>> $filepath 2>&1
# else
# 	echo "/etc/shadow 파일이 없음"	>> $filepath 2>&1
# fi

DividingLine $filepath
echo "리눅스-RHEL 버전별로 패스워드 정책 확인" >> $filepath 2>&1

CheckVersion
if [ $? -eq 7 ]; then
	echo "최소 소문자 요구 1자 이상" >> $filepath 2>&1
	grep -i "lcredit" /etc/security/pwquality.conf >> $filepath 2>&1

	echo "최소 대문자 요구 1자 이상" >> $filepath 2>&1
	grep -i "ucredit" /etc/security/pwquality.conf >> $filepath 2>&1

	echo "최소 숫자 요구 1자 이상" >> $filepath 2>&1
	grep -i "dcredit" /etc/security/pwquality.conf >> $filepath 2>&1

	echo "최소 특수문자 요구 1자 이상" >> $filepath 2>&1
	grep -i "ocredit" /etc/security/pwquality.conf >> $filepath 2>&1

	echo "최소 패스워드 길이 8자 이상" >> $filepath 2>&1
	grep -i "minlen" /etc/security/pwquality.conf >> $filepath 2>&1

	echo "패스워드 입력 실패 재시도 횟수 3번" >> $filepath 2>&1
	grep -i "retry" /etc/security/pwquality.conf >> $filepath 2>&1

	echo "기존 패스워드 비교. 기본값 10(50%)" >> $filepath 2>&1
	grep -i "difok" /etc/security/pwquality.conf >> $filepath 2>&1

	echo "패스워드 기간 만료 경고 알림(7 : 7일이 남은 시점부터 알림)" >> $filepath 2>&1
	grep -i "pass_warn_age" /etc/login.defs >> $filepath 2>&1

	echo "최대 패스워드 사용 기간 설정(60일)" >> $filepath 2>&1
	grep -i "pass_max_days" /etc/login.defs >> $filepath 2>&1

	echo "최소 패스워드 사용 기간 설정(1일 : 최소 1일 경과 후 패스워드 변경 가능)" >> $filepath 2>&1
	grep -i "pass_max_days" /etc/login.defs >> $filepath 2>&1
else
	#centos 6.x 버전
	cat /etc/pam.d/system-auth >> $filepath 2>&1
fi

NewLine $filepath


echo "U-03 Check Start..."
echo "■ U-03. 1. 계정관리 > 1.3 계정 잠금 임계값 설정" >> $filepath 2>&1
echo "■ 기준: /etc/pam.d/system-auth 파일에 아래와 같은 설정이 있으면 양호"	>> $filepath 2>&1
echo "  (auth required /lib/security/pam_tally.so deny=5 unlock_time=120 no_magic_root)"	>> $filepath 2>&1
echo "  (account required /lib/security/pam_tally.so no_magic_root reset)" >> $filepath 2>&1
echo "■ 현황" >> $filepath 2>&1

if grep -i "deny=" /etc/pam.d/system-auth ; then
	echo "U-03,O,," >> $filepath 2>&1
	echo "계정 잠금 임계 값이 설정되어 있어 양호함" >> $filepath 2>&1
else
	echo "U-03,X,," >> $filepath 2>&1
	echo "계정 잠금 임계 값이 설정되어 있지 않아 취약함" >> $filepath 2>&1
fi
echo "[설정]" >> $filepath 2>&1
NewLine $filepath
echo "/etc/pam.d/system-auth 파일 설정(auth, account)"	>> $filepath 2>&1
DividingLine $filepath
cat /etc/pam.d/system-auth | grep -E "auth|account"	>> $filepath 2>&1

NewLine $filepath


echo "U-04 Check Start..."
echo "■ U-04. 1. 계정관리 > 1.4 패스워드 파일 보호" >> $filepath 2>&1
echo "■ 기준: 패스워드가 /etc/shadow 파일에 암호화 되어 저장되고 있으면 양호"	>> $filepath 2>&1
echo "■ 현황" >> $filepath 2>&1

if [ -f /etc/passwd ]; then
	if [ `awk -F : '$2=="x"' /etc/passwd | wc -l` -eq 0 ]; then
		echo "U-04,X,,"	>> $filepath 2>&1
		echo "/etc/passwd 파일에 패스워드가 암호화 되어 있지 않아 취약함"	>> $filepath 2>&1
	else
		echo "U-04,O,,"	>> $filepath 2>&1
		echo "/etc/passwd 파일에 패스워드가 암호화 되어 있어 양호함"	>> $filepath 2>&1
	fi

	NewLine $filepath
	echo "[참고] /etc/passwd Top 5 목록"	>> $filepath 2>&1
	DividingLine $filepath
	cat /etc/passwd | head -5	>> $filepath 2>&1
	echo "이하생략..."	>> $filepath 2>&1
else
	echo "U-04,C,,"	>> $filepath 2>&1
	echo "/etc/passwd 파일이 없음"	>> $filepath 2>&1
fi
echo "[설정]" >> $filepath 2>&1
NewLine $filepath
echo "■ /etc/shadow 파일"	>> $filepath 2>&1
DividingLine $filepath

if [ -f /etc/shadow ]; then
	cat /etc/shadow | head -5	>> $filepath 2>&1
else
	echo "/etc/shadow 파일이 없음"	>> $filepath 2>&1
fi

NewLine $filepath


echo "U-05 Check Start..."
echo "■ U-05. 1. 계정관리 > 1.5 root 이외의 UI가 ‘0’ 금지"	>> $filepath 2>&1
echo "■ 기준: root 계정만이 UID가 0이면 양호"	>> $filepath 2>&1
echo "■ 현황" >> $filepath 2>&1

# UID가 0이 1개이면 양호 2개 이상이면 취약
if [ `awk -F : '$3=="0"' /etc/passwd | wc -l` -eq 1 ]; then
	echo "U-05,O,,"	>> $filepath 2>&1
  echo "root 계정과 동일한 UID를 갖는 계정이 존재하지 않아 양호함" >> $filepath 2>&1
else
  echo "U-05,X,,"	>> $filepath 2>&1
  echo "root 계정과 동일한 UID를 갖는 계정이 존재해 취약함"	>> $filepath 2>&1
fi

echo "[설정]" >> $filepath 2>&1
awk -F : '$3==0 { print $1 " -> UID=" $3 }' /etc/passwd	>> $filepath 2>&1

NewLine $filepath
echo "/etc/passwd 파일 내용"	>> $filepath 2>&1
DividingLine $filepath

cat /etc/passwd	>> $filepath 2>&1

NewLine $filepath


echo "U-06 Check Start..."
echo "■ U-06. 1. 계정관리 > 1.6 root 계정 su 제한" >> $filepath 2>&1
echo "■ 기준: /etc/pam.d/su 파일 설정이 아래와 같을 경우 양호" >> $filepath 2>&1
echo "■ 기준: 아래 설정이 없거나, 주석 처리가 되어 있을 경우 su 명령 파일의 권한이 4750 이면 양호"	>> $filepath 2>&1
echo "  (auth required /lib/security/pam_wheel.so debug group=wheel) 또는"	>> $filepath 2>&1
echo "  (auth required /lib/security/\$ISA/pam_wheel.so use_uid)" >> $filepath 2>&1
echo "■ 현황" >> $filepath 2>&1

#wheel 그룹 : 일반 사용자가 su 명령어 사용 금지
#/etc/pam.d/su 설정 : 일반 사용자가 su 명령은 사용가능하지만 root 로그인을 차단

if [ -f /etc/pam.d/su ]; then
	# pam.d/su 파일에 pam_wheel.so 설정이 있는지 확인
	if [ `cat /etc/pam.d/su | grep 'pam_wheel.so' | grep -v 'trust' | grep -v '^#' | wc -l` -eq 0 ]; then
		# which : 명령어의 전체 경로를 반환

		# su 명령어가 있는지 확인
		if [ `which su | grep -v 'no ' | wc -l` -eq 0 ]; then
			echo "U-06,X,,"	>> $filepath 2>&1
			echo "pam_wheel.so 설정이 없고, su 명령 파일을 찾을 수 없어 취약함"	>> $filepath 2>&1
		else
			sucommand=`which su`;

			# su 명령어 권한 확인
			if [ `stat -c %a $sucommand` -gt 4750 ]; then
				echo "U-06,X,," >> $filepath 2>&1
				echo "pam_wheel.so 설정이 없고, su 명령 파일의 권한이 4750보다 높아 취약함"	>> $filepath 2>&1
			else
				echo "U-06,O,," >> $filepath 2>&1
				echo "pam_wheel.so 설정이 없고, su 명령 파일의 권한이 4750보다 같거나 낮아 양호함" >> $filepath 2>&1
			fi
            echo "[설정]" >> $filepath 2>&1
			ls -al $sucommand	>> $filepath 2>&1
			NewLine $filepath

			# su 명령어의 소유 그룹을 /etc/group에서 찾아서 파일에 기록
			sugroup=`ls -alL $sucommand | awk '{print $4}'`;
			echo "- su명령 그룹(명령파일): `grep -E "^$sugroup" /etc/group`"	>> $filepath 2>&1
		fi
	else
		echo "U-06,O,,"	>> $filepath 2>&1
		echo "pam_wheel.so 설정 내용이 있어 양호함"	>> $filepath 2>&1
	fi
    echo "[설정]" >> $filepath 2>&1
	NewLine $filepath
	echo "/etc/pam.d/su 파일 설정"	>> $filepath 2>&1
	cat /etc/pam.d/su | grep 'pam_wheel.so' | grep -v 'trust'	>> $filepath 2>&1
	DividingLine $filepath

	NewLine $filepath

	if [ `cat /etc/pam.d/su | grep 'pam_wheel.so' | grep -v 'trust' | grep 'group' | awk -F "group=" '{print $2}' | awk -F" " '{print $1}' | wc -l` -gt 0 ]; then
		pamsugroup=`cat /etc/pam.d/su | grep 'pam_wheel.so' | grep -v 'trust' | grep 'group' | awk -F"group=" '{print $2}' | awk -F" " '{print $1}'`
		echo "- su명령 그룹(PAM모듈): `grep -E "^$pamsugroup" /etc/group`"	>> $filepath 2>&1
	else
		if [ `cat /etc/pam.d/su | grep 'pam_wheel.so' | egrep -v 'trust|#' | wc -l` -gt 0 ]; then
			echo "- su명령 그룹(PAM모듈): `grep -E "^wheel" /etc/group`"	>> $filepath 2>&1
		fi
	fi
else
	# /etc/pam.d/su가 없어서 wheel과 파일 권한으로 점검 고려
	echo "U-06,C,," >> $filepath 2>&1
	echo "/etc/pam.d/su 파일을 찾을 수 없음"	>> $filepath 2>&1
fi

NewLine $filepath


echo "U-07 Check Start..."
echo "■ U-07. 1. 계정관리 > 1.7 패스워드 최소 길이 설정" >> $filepath 2>&1
echo "■ 기준: 패스워드 최소 길이가 8자 이상으로 설정되어 있으면 양호"	>> $filepath 2>&1
echo "  (PASS_MIN_LEN 8 이상이면 양호)" >> $filepath 2>&1
echo "■ 현황" >> $filepath 2>&1

CheckVersion
if [ $? -eq 7 ]; then
	#RHEL7
	if [ `grep -i "minlen" /etc/security/pwquality.conf | grep -v '#' | awk '{print $3}'` -ge 8 ]; then
		echo "U-07,O,,"		>> $filepath 2>&1
		echo "패스워드 최소 길이가 8자 이상으로 설정되어 있어 양호함"	>> $filepath 2>&1
	else
		echo "U-07,X,,"		>> $filepath 2>&1
		echo "패스워드 최소 길이가 8자 미만으로 설정되어 있어 취약함"	>> $filepath 2>&1
	fi

	NewLine $filepath
    echo "[설정]" >> $filepath 2>&1
	grep -i "minlen" /etc/security/pwquality.conf >> $filepath 2>&1
else
	if [ `cat /etc/login.defs | grep PASS_MIN_LEN | grep -v '#' | awk '{print $2}'` -ge 8 ]; then
		echo "U-07,O,," >> $filepath 2>&1
		echo "패스워드 최소 길이가 8자 이상으로 설정되어 있어 양호함"	>> $filepath 2>&1
	else
		echo "U-07,X,," >> $filepath 2>&1
		echo "패스워드 최소 길이가 8자 미만으로 설정되어 있어 취약함"	>> $filepath 2>&1
	fi

	NewLine $filepath
    echo "[설정]" >> $filepath 2>&1
	grep -v '^ *#' /etc/login.defs | grep -i "PASS_MIN_LEN"	>> $filepath 2>&1
fi

NewLine $filepath


echo "U-08 Check Start..."
echo "■ U-08. 1. 계정관리 > 1.8 패스워드 최대 사용기간 설정" >> $filepath 2>&1
echo "■ 기준: 패스워드 최대 사용기간이 90일 이하로 설정되어 있으면 양호"	>> $filepath 2>&1
echo "  (PASS_MAX_DAYS 90 이하이면 양호)" >> $filepath 2>&1
echo "■ 현황" >> $filepath 2>&1

if [ `cat /etc/login.defs | grep PASS_MAX_DAYS | grep -v '#' | awk '{print $2}'` -le 90 ]; then
	echo "U-08,O,," >> $filepath 2>&1
	echo "패스워드 최대 사용기간이 90일(12주) 이하로 설정되어 있어 양호함" >> $filepath 2>&1
else
	echo "U-08,X,," >> $filepath 2>&1
	echo "패스워드 최대 사용기간이 90일(12주) 이하로 설정되어 있지 않아 취약함"	>> $filepath 2>&1
fi

NewLine $filepath
echo "[설정]" >> $filepath 2>&1
grep -v '^ *#' /etc/login.defs | grep -i "PASS_MAX_DAYS" >> $filepath 2>&1

NewLine $filepath


echo "U-09 Check Start..."
echo "■ U-09. 1. 계정관리 > 1.9 패스워드 최소 사용기간 설정" >> $filepath 2>&1
echo "■ 기준: 패스워드 최소 사용기간이 1일로 설정되어 있으면 양호"	>> $filepath 2>&1
echo "  (PASS_MIN_DAYS 1 이상이면 양호)" >> $filepath 2>&1
echo "■ 현황" >> $filepath 2>&1

if [ `cat /etc/login.defs | grep PASS_MIN_DAYS | grep -v '#' | awk '{print $2}'` -ge 1 ]; then
	echo "U-09,O,," >> $filepath 2>&1
	echo "패스워드 최소 사용기간이 1일(1주)로 설정되어 있어 양호함" >> $filepath 2>&1
else
	echo "U-09,X,," >> $filepath 2>&1
	echo "패스워드 최소 사용기간이 설정되어 있지 않아 취약함 " >> $filepath 2>&1
fi

NewLine $filepath
echo "[설정]" >> $filepath 2>&1
grep -v '^ *#' /etc/login.defs | grep -i "PASS_MIN_DAYS"	>> $filepath 2>&1

NewLine $filepath


echo "U-10 Check Start..."
echo "■ U-10. 1. 계정관리 > 1.10 불필요한 계정 제거" >> $filepath 2>&1
echo "■ 기준: /etc/passwd 파일에 lp, uucp, nuucp 계정이 모두 제거되어 있으면 양호"	>> $filepath 2>&1
echo "■ 현황" >> $filepath 2>&1

# 주요정보통신기반시설 기술적 취약점 분석평가 가이드에는 UID 100 이하 또는 60000 이상의 계정들은 시스템 계정으로 로그인이 필요없음이라고 서술됨
# 3개의 계정 외에 UID를 기준으로 진단하는 것을 고려
# 일반적으로 영향 없으나 업무 영향도 파악 후 삭제 권고

if [ `cat /etc/passwd | egrep "^lp|^uucp|^nuucp" | wc -l` -eq 0 ]; then
	echo "U-10,O,," >> $filepath 2>&1
	echo "lp, uucp, nuucp 계정이 존재하지 않아 양호함" >> $filepath 2>&1
else
	echo "U-10,X,," >> $filepath 2>&1
	echo "lp, uucp, nuucp 계정이 존재해 취약함" >> $filepath 2>&1
fi

echo "[설정]" >> $filepath 2>&1
cat /etc/passwd | egrep "^lp|^uucp|^nuucp"	>> $filepath 2>&1

NewLine $filepath


echo "U-11 Check Start..."
echo "■ U-11. 관리자 그룹에 최소한의 계정 포함" >> $filepath 2>&1
echo "■ 기준: 관리자 계정이 포함된 그룹에 불필요한 계정이 존재하지 않는 경우 양호"	>> $filepath 2>&1
echo "■ 현황" >> $filepath 2>&1

echo "U-11,C,," >> $filepath 2>&1
echo "[수동진단]관리자 계정이 포함된 그룹에 불필요한 계정이 존재 유뮤 확인 필요"	>> $filepath 2>&1

echo "[설정]" >> $filepath 2>&1
echo "① 관리자 계정" >> $filepath 2>&1
DividingLine $filepath
if [ -f /etc/passwd ]; then
	# UID가 0인 계정 이름과 GID를 기록
	awk -F : '$4==0 { print $1 " -> GID=" $4 }' /etc/passwd	>> $filepath 2>&1
else
	echo "/etc/passwd 파일이 없음" >> $filepath 2>&1
fi

NewLine $filepath
echo "② 관리자 계정이 포함된 그룹 확인" >> $filepath 2>&1
DividingLine $filepath

# UID가 0인 계정으로 /etc/group의 내용을 검색해서 기록
for group in `awk -F: '$4==0 {print $1}' /etc/passwd`; do
	cat /etc/group | grep "$group"	>> $filepath 2>&1
done

# NewLine $filepath
# echo "[참고] /etc/group 파일"	>> $filepath 2>&1
# DividingLine $filepath
# cat /etc/group	>> $filepath 2>&1

NewLine $filepath


echo "U-12 Check Start..."
echo "■ U-12. 1. 계정관리 > 1.12 계정이 존재하지 않는 GID 금지" >> $filepath 2>&1
echo "■ 기준: 구성원이 존재하지 않는 빈 그룹이 발견되지 않을 경우 양호"	>> $filepath 2>&1
echo "■ 현황" >> $filepath 2>&1

# 빈 그룹이어도 /etc/passwd에 존재하는 계정의 그룹인 경우가 있기 때문에 /etc/passwd와 /etc/group를 비교함

# /etc/group에서 구성원이 없는 빈그룹을 추출
for gname in `awk -F : '$4==null' /etc/group`; do
	# 그룹 이름만 추출
	U51GNAME=`echo $gname | awk -F : '{print $1}'`

	# 그룹 이름이 /etc/passwd 목록에 없으면 그룹 정보를 파일에 기록
	if ! grep "^$U12GNAME:" /etc/passwd ; then
		echo $gname >> U51GroupNameList.txt
	fi
done

if [ `awk -F: '$4==null' /etc/group | wc -l` -eq 0 ]; then
	echo "U-12,O,," >> $filepath 2>&1
	echo "구성원이 존재하지 않는 그룹이 발견되지 않아 양호함"	>> $filepath 2>&1
else
	echo "U-12,X,," >> $filepath 2>&1
	echo "구성원이 존재하지 않는 그룹이 발견되어 취약함"	>> $filepath 2>&1
fi

echo "[설정]" >> $filepath 2>&1
NewLine $filepath
echo "구성원이 존재하지 않는 그룹"	>> $filepath 2>&1
DividingLine $filepath
cat U51GroupNameList.txt >> $filepath 2>&1

rm -f U51GroupNameList.txt

NewLine $filepath


echo "U-13 Check Start..."
echo "■ U-13. 1. 계정관리 > 1.13 동일한 UID 금지" >> $filepath 2>&1
echo "■ 기준: 동일한 UID로 설정된 계정이 존재하지 않을 경우 양호"	>> $filepath 2>&1
echo "■ 현황" >> $filepath 2>&1

# /etc/passwd에서 UID만 추출
for uid in `cat /etc/passwd | awk -F: '{print $3}'`; do
	# /etc/passwd에서 추출한 UID로 검색하여 equaluid.txt에 기록
	cat /etc/passwd | awk -F: '$3=="'${uid}'" { print "UID=" $3 " -> " $1 }'	> equaluid.txt

	# equaluid.txt의 줄 수가 2줄 이상이면 중복된 UID가 존재해서 total-equaluid.txt에 기록
	if [ `cat equaluid.txt | wc -l` -gt 1 ]; then
		cat equaluid.txt	>> total-equaluid.txt
	fi
done

# total-equaluid.txt가 2줄 이상이면 취약
if [ `cat total-equaluid.txt | wc -l` -gt 1 ]; then
	echo "U-13,X,," >> $filepath 2>&1
	echo "동일한 UID를 사용하는 계정이 발견되어 취약함"	>> $filepath 2>&1

    echo "[설정]" >> $filepath 2>&1
	NewLine $filepath
	echo "동일한 UID를 사용하는 계정 "	>> $filepath 2>&1
	DividingLine $filepath

	#uid로 오름차순으로 정렬 후 uniq로 중복 제거하고 파일에 기록
	sort -k 1 total-equaluid.txt | uniq -d	>> $filepath 2>&1
else
	echo "U-13,O,," >> $filepath 2>&1
	echo "동일한 UID를 사용하는 계정이 발견되지 않아 양호함"	>> $filepath 2>&1
fi

rm -f equaluid.txt
rm -f total-equaluid.txt

NewLine $filepath


echo "U-14 Check Start..."
echo "■ U-14. 1. 계정관리 > 1.14 사용자 shell 점검"	>> $filepath 2>&1
echo "■ 기준: 로그인이 필요하지 않은 시스템 계정에 /bin/false 또는 /sbin/nologin 쉘이 부여되어 있으면 양호"	>> $filepath 2>&1
echo "■ 현황" >> $filepath 2>&1

# 불필요한 계정은 시스템 용도에 따라 차이가 있음
# 아래 계정 목록은 주요정보통신기반시설 취약점 분석평가 가이드의 목록을 참조

# /etc/passwd에서 순차적으로 검색
# 1. 계정 목록으로 시작되는 행을 검색
# 2. 검색된 목록 중 admin이 포함 안 된 행을 검색
# 3. 검색된 목록 중 /bin/false 또는 /sbin/nologin가 포함 안 된 행을 검색
# 4. 검색된 행 숫자를 비교
# 5. 0이면 양호 아니면 취약

if [ `cat /etc/passwd | egrep "^daemon|^bin|^sys|^adm|^listen|^nobody|^nobody4|^noaccess|^diag|^listen|^operator|^games|^gopher" | grep -v "admin" | egrep -v -i "/bin/false|/sbin/nologin" | wc -l` -eq 0 ]; then
	echo "U-14,O,," >> $filepath 2>&1
	echo "로그인이 필요하지 않은 계정에 /bin/false(/sbin/nologin) 쉘이 부여되어 있어 양호함" >> $filepath 2>&1
else
	echo "U-14,X,," >> $filepath 2>&1
	echo "로그인이 필요하지 않은 계정에 /bin/false(/sbin/nologin) 쉘이 부여되지 않아 취약함" >> $filepath 2>&1
fi

echo "[설정]" >> $filepath 2>&1
NewLine $filepath
echo "로그인이 필요하지 않은 시스템 계정 확인"	>> $filepath 2>&1
DividingLine $filepath
cat /etc/passwd | egrep "^daemon|^bin|^sys|^adm|^listen|^nobody|^nobody4|^noaccess|^diag|^listen|^operator|^games|^gopher" | grep -v "admin"	>> $filepath 2>&1

NewLine $filepath


echo "U-15 Check Start..."
echo "■ U-15. 1. 계정관리 > 1.15 Session Timeout 설정" >> $filepath 2>&1
echo "■ 기준: /etc/profile 에서 TMOUT=600 이하 또는 /etc/csh.login 에서 autologout=10 이하로 설정되어 있으면 양호"	>> $filepath 2>&1
echo "  (1) sh, ksh, bash 쉘의 경우 /etc/profile 파일 설정을 적용받음" >> $filepath 2>&1
echo "  (2) csh, tcsh 쉘의 경우 /etc/csh.cshrc 또는 /etc/csh.login 파일 설정을 적용받음"	>> $filepath 2>&1
echo "■ 현황" >> $filepath 2>&1

# 모니터링 용도이면 업무가 불가능하므로 예외처리

# 쉘 확인
chkSH=`CheckShell`
case $chkSH in
	'sh'|'ksh'|'bash')
		# /etc/profile
		if [ -f /etc/profile ]; then
			# TMOUT이 600초 이하이면 양호
			if [ `cat /etc/profile | grep -i TMOUT | grep -v "^#" | awk -F "=" '{print $2}'` -le 600 ]; then
				echo "U-15,O,,"	>> $filepath 2>&1
				echo "TMOUT이 600초 이하로 설정되어 있어 양호함"	>> $filepath 2>&1
                echo "[설정]" >> $filepath 2>&1
				cat /etc/profile | grep -i TMOUT | grep -v "^#"	>> $filepath 2>&1
			else
				echo "U-15,X,,"	>> $filepath 2>&1
				echo "TMOUT이 600초 초과하거나 설정이 없어 취약함" >> $filepath 2>&1
                echo "[설정]" >> $filepath 2>&1
				cat /etc/profile | grep -i TMOUT	>> $filepath 2>&1
			fi
		else
			echo "U-15,X,,"	>> $filepath 2>&1
			echo "/etc/profile 파일이 없어 취약함"	>> $filepath 2>&1
		fi
		;;

	'csh'|'tcsh')
		# /etc/csh.cshrc 또는 /etc/csh.login
		if [ -f /etc/csh.cshrc ]; then
			# autologout이 10분 이하이면 양호
			if [ `cat /etc/csh.cshrc | grep -i autologout | grep -v "^#" | awk -F "=" '{print $2}'` -le 10 ]; then
				echo "U-15,O,,"	>> $filepath 2>&1
				echo "autologout이 10분 이하로 설정되어 있어 양호함"	>> $filepath 2>&1
                echo "[설정]" >> $filepath 2>&1
				cat /etc/csh.cshrc | grep -i autologout	>> $filepath 2>&1

				break
			fi
		fi

		if [ -f /etc/csh.login ]; then
			# autologout이 10분 이하이면 양호
			if [ `cat /etc/csh.login | grep -i autologout | grep -v "^#" | awk -F "=" '{print $2}'` -le 10 ]; then
				echo "U-15,O,,"	>> $filepath 2>&1
				echo "autologout이 10분 이하로 설정되어 있어 양호함"	>> $filepath 2>&1
                echo "[설정]" >> $filepath 2>&1
				cat /etc/csh.login | grep -i autologout	>> $filepath 2>&1
			else
				echo "U-15,X,,"	>> $filepath 2>&1
				echo "/etc/csh.cshrc과 /etc/csh.login 파일이 없거나 autologout이 10분 초과해 취약함"	>> $filepath 2>&1
			fi
		else
			echo "U-15,X,,"	>> $filepath 2>&1
			echo "/etc/csh.cshrc과 /etc/csh.login 파일이 없거나 autologout이 10분 초과해 취약함"	>> $filepath 2>&1
		fi
		;;

	*)
		echo "U-15,C,,"	>> $filepath 2>&1
		echo "정의된 쉘이 아니므로 수동 검사"	>> $filepath 2>&1
		;;
esac

NewLine $filepath



echo "U-16 Check Start..."
echo "■ U-16. 2. 파일 및 디렉토리 관리 > 2.1 root 홈, 패스 디렉터리 권한 및 패스 설정" >> $filepath 2>&1
echo "■ 기준: Path 설정에 "." 이 맨 앞이나 중간에 포함되어 있지 않을 경우 양호"	>> $filepath 2>&1
echo "■ 현황" >> $filepath 2>&1

# $PATH의 끝에서 . 또는 :: 을 제외하고 있는지 확인 필요

# :: 판단
# :: 이 있는지 확인(수량도 같이 확인)
# :: 이 끝에 있는지 확인
case `echo $PATH | grep '::' | wc -l` in
	0)
		# . 판단

		# . 만 있는 위치
		checkPoint=-1

		# . 만 있는 위치의 총 개수
		TotalPoint=0

		# $PATH에 있는 경로 전체 개수
		LoopCount=0
		for i in $(echo $IN | tr ":" "\n"); do
			LoopCount=$((LoopCount + 1))

			# . 만 있는지 확인
			if [ "$i" = "." ]; then
				checkPoint=$LoopCount
				TotalPoint=$((TotalPoint + 1))
			fi
		done

		if [ $checkPoint -eq -1 ]; then
			# -1이면 .이 없음
			echo "U-16,O,,"	>> $filepath 2>&1
			echo "PATH 환경변수에 "." 이 맨 앞이나 중간에 포함되지 않아 양호함" >> $filepath 2>&1
		elif [ $TotalPoint -gt 1 ]; then
			# .만 있는 경로 개수가 1보다 큰 경우
			echo "U-16,X,,"	>> $filepath 2>&1
			echo "PATH 환경변수에 "." 이 맨 앞이나 중간에 포함되어 있어 취약함" >> $filepath 2>&1
		elif [ $checkPoint -eq $LoopCount ]; then
			# .만 있는 경로가 마지막에 있는 경우
			echo "U-16,O,,"	>> $filepath 2>&1
			echo "PATH 환경변수에 "." 이 맨 앞이나 중간에 포함되지 않아 양호함" >> $filepath 2>&1
		else
			# 나머지는 .만 있는 경로가 처음 또는 중간에 포함되는 경우
			echo "U-16,X,,"	>> $filepath 2>&1
			echo "PATH 환경변수에 "." 이 맨 앞이나 중간에 포함되어 있어 취약함" >> $filepath 2>&1
		fi
		;;

	1)
		# ::가 끝에 없으면 취약
		if [ `echo $PATH | grep '::$' | wc -l` -eq 1 ]; then
			echo "U-16,O,,"	>> $filepath 2>&1
			echo "PATH 환경변수에 "." 이 맨 앞이나 중간에 포함되지 않아 양호함" >> $filepath 2>&1
		else
			echo "U-16,X,,"	>> $filepath 2>&1
			echo "PATH 환경변수에 "." 이 맨 앞이나 중간에 포함되어 있어 취약함" >> $filepath 2>&1
		fi
		;;

	*)
		# ::가 2개 이상이므로 끝에 있어도 처음이나 중간에 있다고 판단하므로 취약
		echo "U-16,X,,"	>> $filepath 2>&1
		echo "PATH 환경변수에 "." 이 맨 앞이나 중간에 포함되어 있어 취약함" >> $filepath 2>&1
		;;
esac

echo "[설정]" >> $filepath 2>&1
echo "PATH 설정 확인"	>> $filepath 2>&1
DividingLine $filepath
echo $PATH	>> $filepath 2>&1

NewLine $filepath


echo "U-17 Check Start..."
echo "■ U-17. 2. 파일 및 디렉토리 관리 > 2.2 파일 및 디렉터리 소유자 설정" >> $filepath 2>&1
echo "■ 기준: 소유자가 존재하지 않은 파일 및 디렉터리가 존재하지 않을 경우 양호"	>> $filepath 2>&1
echo "■ 현황" >> $filepath 2>&1

U_DATA_17_1='U_DATA_17_1.txt'

if [ $filecheck_pass -eq 0 ]; then
	if [ -d /etc ]; then
		find /etc -nouser -print | grep '^/' >> $U_DATA_17_1
		find /etc -nogroup -print | grep '^/' >> $U_DATA_17_1
	fi

	if [ -d /var ]; then
		find /var -nouser -print | grep '^/' >> $U_DATA_17_1
		find /var -nogroup -print | grep '^/' >> $U_DATA_17_1
	fi

	if [ -d /tmp ]; then
		find /tmp -nouser -print | grep '^/' >> $U_DATA_17_1
		find /tmp -nogroup -print | grep '^/' >> $U_DATA_17_1
	fi

	if [ -d /home ]; then
		find /home -nouser -print | grep '^/' >> $U_DATA_17_1
		find /home -nogroup -print | grep '^/' >> $U_DATA_17_1
	fi

	if [ -d /export ]; then
		find /export -nouser -print | grep '^/' >> $U_DATA_17_1
		find /export -nogroup -print | grep '^/' >> $U_DATA_17_1
	fi

	if [ `cat $U_DATA_17_1 | wc -l` -eq 0 ]; then
		echo "U-17,O,,"		>> $filepath 2>&1
		echo "소유자가 존재하지 않는 파일이 발견되지 않아 양호함"	>> $filepath 2>&1
	else
		echo "U-17,X,,"		>> $filepath 2>&1
		echo "소유자가 존재하지 않는 파일이 발견되어 취약함"	>> $filepath 2>&1

        echo "[설정]" >> $filepath 2>&1
		NewLine $filepath
		DividingLine $filepath
		cat $U_DATA_17_1	>> $filepath 2>&1
		DividingLine $filepath
	fi

	rm -f $U_DATA_17_1
else
	echo "U-17,C,,"		>> $filepath 2>&1
	NewLine $filepath
	echo "[수동진단] 담당자 인터뷰 필요-파일 검사 시간 지연(10분 이상)"	>> $filepath 2>&1
fi

NewLine $filepath


echo "U-18 Check Start..."
echo "■ U-18.2. 파일 및 디렉토리 관리 > 2.3 /etc/passwd 파일 소유자 및 권한 설정" >> $filepath 2>&1
echo "■ 기준: /etc/passwd 파일의 소유자가 root 이고, 권한이 644 이하이면 양호"	>> $filepath 2>&1
echo "■ 현황" >> $filepath 2>&1

# /etc/passwd 파일 유무 확인
if [ -f /etc/passwd ]; then
	# /etc/passwd 소유자 root 확인
	if [ `ls -alL /etc/passwd | awk '{print $3}'` = 'root' ]; then
		# /etc/passwd 권한이 644보다 높은지 확인
		if [ `stat -c %a /etc/passwd` -gt 644 ]; then
			echo "U-18,X,,"	>> $filepath 2>&1
			echo "/etc/passwd 파일의 소유자가 root이고 권한이 644보다 높아 취약함"	>> $filepath 2>&1
            echo "[설정]" >> $filepath 2>&1
			ls -alL /etc/passwd	>> $filepath 2>&1
		else
			echo "U-18,O,,"	>> $filepath 2>&1
			echo "/etc/passwd 파일의 소유자가 root이고 권한이 644 이하로 설정되어 양호함"	>> $filepath 2>&1
            echo "[설정]" >> $filepath 2>&1
			ls -alL /etc/passwd	>> $filepath 2>&1
		fi
	else
		echo "U-18,X,,"	>> $filepath 2>&1
		echo "/etc/passwd 파일의 소유자가 root가 아니므로 취약함"	>> $filepath 2>&1
        echo "[설정]" >> $filepath 2>&1
		ls -alL /etc/passwd	>> $filepath 2>&1
		NewLine $filepath
	fi
else
	echo "U-18,C,,"	>> $filepath 2>&1
	echo "[수동진단]/etc/passwd 파일이 없음"	>> $filepath 2>&1
fi

NewLine $filepath


echo "U-19 Check Start..."
echo "■ U-19. 2. 파일 및 디렉토리 관리 > 2.4 /etc/shadow 파일 소유자 및 권한 설정" >> $filepath 2>&1
echo "■ 기준: /etc/shadow 파일의 소유자가 root 이고, 권한이 400 이하이면 양호"	>> $filepath 2>&1
echo "■ 현황" >> $filepath 2>&1

if [ -f /etc/shadow ]; then
	if [ `ls -alL /etc/shadow | awk '{print $3}'` = 'root' ]; then
		if [ `stat -c %a /etc/shadow` -le 400 ]; then
			echo "U-19,O,,"	>> $filepath 2>&1
			echo "/etc/shadow 파일의 소유자가 root이며 파일의 권한이 400 이하로 설정되어 양호함"	>> $filepath 2>&1
            echo "[설정]" >> $filepath 2>&1
			ls -alL /etc/shadow	>> $filepath 2>&1
		else
			echo "U-19,X,,"	>> $filepath 2>&1
			echo "/etc/shadow 파일의 소유자가 root이며 파일의 권한이 400보다 높아 취약함"	>> $filepath 2>&1
            echo "[설정]" >> $filepath 2>&1
			ls -alL /etc/shadow	>> $filepath 2>&1
		fi
	else
		echo "U-19,X,,"	>> $filepath 2>&1
		echo "/etc/shadow 파일의 소유자가 root가 아니므로 취약함"	>> $filepath 2>&1
        echo "[설정]" >> $filepath 2>&1
		ls -alL /etc/shadow	>> $filepath 2>&1
	fi
else
	echo "U-19,C,,"	>> $filepath 2>&1
	echo "[수동진단]/etc/shadow 파일이 없음"	>> $filepath 2>&1
fi

NewLine $filepath


echo "U-20 Check Start..."
echo "■ U-20. 2. 파일 및 디렉토리 관리 > 2.5 /etc/hosts 파일 소유자 및 권한 설정" >> $filepath 2>&1
echo "■ 기준: /etc/hosts 파일의 소유자가 root 이고, 권한이 600 이하이면 양호"	>> $filepath 2>&1
echo "■ 현황" >> $filepath 2>&1

if [ -f /etc/hosts ]; then
	if [ `ls -alL /etc/hosts | awk '{print $3}'` = 'root' ]; then
		if [ `stat -c %a /etc/hosts` -le 600 ]; then
			echo "U-20,O,,"	>> $filepath 2>&1
			echo "/etc/hosts 파일의 소유자가 root이며 파일의 권한이 600 이하로 설정되어 양호함"	>> $filepath 2>&1
            echo "[설정]" >> $filepath 2>&1
			ls -alL /etc/hosts	>> $filepath 2>&1
		else
			echo "U-20,X,,"	>> $filepath 2>&1
			echo "/etc/hosts 파일의 소유자가 root이며 파일의 권한이 600보다 높아 취약함"	>> $filepath 2>&1
            echo "[설정]" >> $filepath 2>&1
			ls -alL /etc/hosts	>> $filepath 2>&1
		fi
	else
		echo "U-20,X,,"	>> $filepath 2>&1
		echo "/etc/hosts 파일의 소유자가 root가 아니므로 취약함"	>> $filepath 2>&1
        echo "[설정]" >> $filepath 2>&1
		ls -alL /etc/hosts	>> $filepath 2>&1
	fi
else
	echo "U-20,C,,"	>> $filepath 2>&1
	echo "[수동진단]/etc/hosts 파일이 없음"	>> $filepath 2>&1
fi

NewLine $filepath



echo "U-21 Check Start..."
echo "■ U-21. 2. 파일 및 디렉토리 관리 > 2.6 /etc/(x)inetd.conf 파일 소유자 및 권한 설정"	>> $filepath 2>&1
echo "■ 기준: /etc/(x)inetd.conf 파일 및 /etc/xinetd.d/ 하위 모든 파일의 소유자가 root이고, 권한이 600 이하이면 양호"	>> $filepath 2>&1
echo "■ 현황"	>> $filepath 2>&1

# error code
# 0 : 양호
# 1 : 취약
# 2 : 파일 없음

# inetd.conf 확인
if [ -f /etc/inetd.conf ]; then
	if [ `ls -alL /etc/inetd.conf | awk '{print $3}'` = 'root' ]; then
		if [ `stat -c %a /etc/inetd.conf` -le 600 ]; then
			#echo "U-21,O,,"	>> $filepath 2>&1
			#echo "/etc/inetd.conf 파일의 소유자가 root이며 파일의 권한이 600임"	>> $filepath 2>&1
			#ls -alL /etc/inetd.conf	>> $filepath 2>&1

			u21checkinet=0
			u21strinet="/etc/inetd.conf 파일의 소유자가 root이며 파일의 권한이 600보다 낮거나 같음"
		else
			#echo "U-21,X,,"	>> $filepath 2>&1
			#echo "/etc/inetd.conf 파일의 소유자가 root이며 파일의 권한이 600이 아님"	>> $filepath 2>&1
			#ls -alL /etc/inetd.conf	>> $filepath 2>&1

			u21checkinet=1
			u21strinet="/etc/inetd.conf 파일의 소유자가 root이며 파일의 권한이 600보다 높음"
		fi
	else
		#echo "U-21,X,,"	>> $filepath 2>&1
		#echo "/etc/inetd.conf 파일의 소유자가 root가 아님"	>> $filepath 2>&1
		#ls -alL /etc/inetd.conf	>> $filepath 2>&1

		u21checkinet=1
		u21strinet="/etc/inetd.conf 파일의 소유자가 root가 아님"
	fi
else
	#echo "U-21,C,,"	>> $filepath 2>&1
	#echo "/etc/inetd.conf 파일이 없음"	>> $filepath 2>&1

	u21checkinet=2
	u21strinet="/etc/inetd.conf 파일이 없음"
fi

# xientd.conf 확인
if [ -f /etc/xinetd.conf ]; then
	if [ `ls -alL /etc/xinetd.conf | awk '{print $3}'` = 'root' ]; then
		if [ `stat -c %a /etc/xinetd.conf` -le 600 ]; then
			#echo "U-21,O,,"	>> $filepath 2>&1
			#echo "/etc/xinetd.conf 파일의 소유자가 root이며 파일의 권한이 600임"	>> $filepath 2>&1
			#ls -alL /etc/xinetd.conf	>> $filepath 2>&1

			u21checkxinet=0
			u21strxinet="/etc/xinetd.conf 파일의 소유자가 root이며 파일의 권한이 600보다 낮거나 같음"
		else
			#echo "U-21,X,,"	>> $filepath 2>&1
			#echo "/etc/xinetd.conf 파일의 소유자가 root이며 파일의 권한이 600이 아님"	>> $filepath 2>&1
			#ls -alL /etc/xinetd.conf	>> $filepath 2>&1

			u21checkxinet=1
			u21strxinet="/etc/xinetd.conf 파일의 소유자가 root이며 파일의 권한이 600보다 높음"
		fi
	else
		#echo "U-21,X,,"	>> $filepath 2>&1
		#echo "/etc/xinetd.conf 파일의 소유자가 root가 아님"	>> $filepath 2>&1
		#ls -alL /etc/xinetd.conf	>> $filepath 2>&1

		u21checkxinet=1
		u21strxinet="/etc/xinetd.conf 파일의 소유자가 root가 아님"
	fi
else
	#echo "U-21,C,,"	>> $filepath 2>&1
	#echo "/etc/xinetd.conf 파일이 없음"	>> $filepath 2>&1

	u21checkxinet=2
	u21strxinet="/etc/xinetd.conf 파일이 없음"
fi

u21checkxinetd=0
u21strxinetd='U-21xinetd.tmp'

# xinetd.d 디렉터리 하위 파일 확인
if [ -d "/etc/xinetd.d" ]; then
	# xinetd.d 디렉터리 하위에 디렉터리가 있는 경우에는 검사가 안됨 -> 필요하면 for문 안에 -d 확인 후 for문으로 파일 검사 진행
	for file in "/etc/xinetd.d"/*; 	do
		#echo 'filename : '$file
		if [ `ls -alL $file | awk '{print $3}'` = 'root' ]; then
			if [ `stat -c %a $file` -le 600 ]; then
				echo $file" 파일의 소유자가 root이며 파일의 권한이 600보다 낮거나 같음" >> $u21strxinetd 2>&1
			else
				echo $file" 파일의 소유자가 root이며 파일의 권한이 600보다 높음" >> $u21strxinetd 2>&1

				# 파일 중 1개라도 오류가 발생하면 취약
				u21checkxinetd=1
			fi
		else
			echo $file' 파일의 소유자가 root가 아님' >> $u21strxinetd 2>&1

			# 파일 중 1개라도 오류가 발생하면 취약
			u21checkxinetd=1
		fi
	done
else
	echo "/etc/xinetd.d 디렉터리가 없음" >> $u21strxinetd 2>&1
fi

# 3개 중 1개라도 1인 경우가 있으면 취약
if [ $u21checkinet -eq 1 ] || [ $u21checkxinet -eq 1 ] || [ $u21checkxinetd -eq 1 ]; then
	echo "U-21,X,,"	>> $filepath 2>&1
    echo "[설정]" >> $filepath 2>&1
	NewLine $filepath

	echo '/etc/inetd.conf 결과' >> $filepath 2>&1
	DividingLine $filepath
	echo $u21strinet >> $filepath 2>&1
	NewLine $filepath

	echo '/etc/xinetd.conf 결과' >> $filepath 2>&1
	DividingLine $filepath
	echo $u21strxinet >> $filepath 2>&1
	NewLine $filepath

	echo '/etc/xientd.d 결과' >> $filepath 2>&1
	DividingLine $filepath
	cat $u21strxinetd >> $filepath 2>&1
else
	echo "U-21,O,,"	>> $filepath 2>&1
	echo "/etc/inetd.conf 파일의 소유자가 root이며 파일의 권한이 600보다 낮거나 같아 양호함"	>> $filepath 2>&1
fi

# 임시 파일 파일 정리
rm -f $u21strxinetd

NewLine $filepath



echo "U-22 Check Start..."
echo "■ U-22. 2. 파일 및 디렉토리 관리 > 2.7 /etc/syslog.conf 파일 소유자 및 권한 설정"	>> $filepath 2>&1
echo "■ 기준: /etc/syslog.conf 파일의 소유자가 root(또는 bin, sys)이고 권한이 644 이하이면 양호"	>> $filepath 2>&1
echo "■ 현황"	>> $filepath 2>&1

# 기본적으로 /etc/syslog.conf를 확인
# Linux(CentOS 6 이상)이면 rsyslog.conf를 확인

if [ -f /etc/syslog.conf ]; then
	u22sysuser=`ls -alL /etc/syslog.conf | awk '{print $3}'`
	if [ $u22sysuser = 'root' ] || [ $u22sysuser = 'bin' ] || [ $u22sysuser = 'sys' ]; then
		if [ `stat -c %a /etc/syslog.conf` -gt 644 ]
		then
			echo "U-22,X,," >> $filepath 2>&1
			echo "/etc/syslog.conf 파일의 권한이 644보다 높아 취약함"	>> $filepath 2>&1
		else
			echo "U-22,O,," >> $filepath 2>&1
			echo "/etc/syslog.conf 파일의 소유자가 root|bin|sys이고 파일의 권한이 644보다 낮거나 같아 양호함"	>> $filepath 2>&1
		fi
	else
		echo "U-22,X,," >> $filepath 2>&1
		echo "/etc/syslog.conf 파일의 소유자가 root|bin|sys 중에 없어 취약함"	>> $filepath 2>&1
	fi
    echo "[설정]" >> $filepath 2>&1
	ls -alL /etc/syslog.conf	>> $filepath 2>&1
elif [ -f /etc/rsyslog.conf ]; then
	u22rsysuser=`ls -alL /etc/rsyslog.conf | awk '{print $3}'`
	if [ $u22rsysuser = 'root' ] || [ $u22rsysuser = 'bin' ] || [ $u22rsysuser = 'sys' ]; then
		if [ `stat -c %a /etc/rsyslog.conf` -gt 644 ]; then
			echo "U-22,X,," >> $filepath 2>&1
			echo "/etc/rsyslog.conf 파일의 소유자가 root|bin|sys이고 파일의 권한이 644보다 높아 취약함"	>> $filepath 2>&1
		else
			echo "U-22,O,," >> $filepath 2>&1
			echo "/etc/rsyslog.conf 파일의 소유자가 root|bin|sys이고 파일의 권한이 644보다 낮거나 같아 양호함"	>> $filepath 2>&1
		fi
	else
		echo "U-22,X,," >> $filepath 2>&1
		echo "/etc/rsyslog.conf 파일의 소유자가 root|bin|sys가 아닌 다른 소유자 이므로 취약함"	>> $filepath 2>&1
	fi
    echo "[설정]" >> $filepath 2>&1
	ls -alL /etc/rsyslog.conf	>> $filepath 2>&1
else
	echo "U-22,C,," >> $filepath 2>&1
	echo "/etc/syslog.conf 또는 /etc/rsyslog.conf 파일이 없음"	>> $filepath 2>&1
fi

NewLine $filepath



echo "U-23 Check Start..."
echo "■ U-23. 2. 파일 및 디렉토리 관리 > 2.8 /etc/services 파일 소유자 및 권한 설정"	>> $filepath 2>&1
echo "■ 기준: /etc/services 파일의 권한이 644 이하이면 양호"	>> $filepath 2>&1
echo "■ 현황" >> $filepath 2>&1

if [ -f /etc/services ]; then
	if [ `ls -alL /etc/services | awk '{print $3}'` = 'root' ]; then
		if [ `stat -c %a /etc/services` -le 644 ]; then
			echo "U-23,O,,"	>> $filepath 2>&1
			echo "/etc/services 파일의 소유자가 root이고 파일의 권한이 644보다 낮거나 같아 양호함"	>> $filepath 2>&1
		else
			echo "U-23,X,,"	>> $filepath 2>&1
			echo "/etc/services 파일의 소유자가 root이고 파일의 권한이 644보다 높아 취약함" >> $filepath 2>&1
		fi
	else
		echo "U-23,X,,"	>> $filepath 2>&1
		echo "/etc/services 파일의 소유자가 root가 아니므로 취약함"	>> $filepath 2>&1
	fi
    echo "[설정]" >> $filepath 2>&1
	ls -alL /etc/services	>> $filepath 2>&1
else
	echo "U-23,C,,"	>> $filepath 2>&1
	echo "/etc/services 파일이 없음"	>> $filepath 2>&1
fi

NewLine $filepath


echo "U-24 Check Start..."
echo "■ U-24. 2. 파일 및 디렉토리 관리 > 2.9 SUID, SGID, Sticky bit 설정파일 점검" >> $filepath 2>&1
echo "■ 기준: 불필요한 SUID/SGID 설정이 존재하지 않을 경우 양호"	>> $filepath 2>&1
echo "■ 현황" >> $filepath 2>&1

# Linux 불필요한 SUID/SGID 목록(주요정보통신기반시설 기술적 취약점 분석평가 가이드.pdf)
u24array_superfluous=(
'/sbin/dump'
'/sbin/restore'
'/sbin/unix_chkpwd'
'/usr/bin/at'
'/usr/bin/lpq'
'/usr/bin/lpq-lpd'
'/usr/bin/lpr'
'/usr/bin/lpr-lpd'
'/usr/bin/lprm'
'/usr/bin/lprm-lpd'
'/usr/bin/newgrp'
'/usr/sbin/lpc'
'/usr/sbin/lpc-lpd'
'/usr/sbin/traceroute'
)

if [ $filecheck_pass -eq 0 ]; then
	# SUID/SGID 검색 결과 파일
	u24search='U-24search.tmp'

	# 불필요한 목록이 /usr와 /sbin이므로 2곳에서만 검색
	# 필요하면 추가하거나 /에서 검색으로 변경
	find /usr -xdev -user root -type f \( -perm -04000 -o -perm -02000 \) -exec ls -al  {}  \; >> $u24search 2>&1
	find /sbin -xdev -user root -type f \( -perm -04000 -o -perm -02000 \) -exec ls -al  {}  \; >> $u24search 2>&1

	# 검색 결과 중 불필요한 목록이 있으면 기록되는 파일
	u24check='U-24check.tmp'

	# 불필요한 목록을 하나씩 검색 결과 파일에서 찾기
	for sf in "${u24array_superfluous[@]}"; do
		# 검색 결과에 불필요한 목록이 있으면 파일에 쓰기
		if [ `cat $u24search | grep $sf | wc -l` -gt 0 ]; then
			cat $u24search | grep $sf >> $u24check 2>&1
		fi
	done

	# 파일 크기가 0보다 큰지 확인
	if [ -s $u24check ]; then
		echo "U-24,X,,"	>> $filepath 2>&1
		NewLine $filepath
		echo "주요 파일의 권한에 SUID/SGID로 설정된 파일이 발견되어 취약함"	>> $filepath 2>&1
        echo "[설정]" >> $filepath 2>&1
		cat $u24check	>> $filepath 2>&1
	else
		echo "U-24,O,,"	>> $filepath 2>&1
		NewLine $filepath
		echo "주요 파일의 권한에 SUID/SGID로 설정된 파일이 발견되지 않아 양호함"	>> $filepath 2>&1
	fi

	# 파일 정리
	rm -f $u24search
	rm -f $u24check
else
	echo "U-24,C,,"	>> $filepath 2>&1
	NewLine $filepath
	echo "[수동진단] 담당자 인터뷰 필요-파일 검사 시간 지연(10분 이상)"	>> $filepath 2>&1
fi

NewLine $filepath



echo "U-25 Check Start..."
echo "■ U-25. 2. 파일 및 디렉토리 관리 > 2.10 사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정" >> $filepath 2>&1
echo "■ 기준: 홈디렉터리 환경변수 파일에 소유자가 root 또는 해당 계정으로 지정되고 타사용자 쓰기 권한이 제거되어 있으면 양호"	>> $filepath 2>&1
echo "■ 현황"	>> $filepath 2>&1

if [ $filecheck_pass -eq 0 ]; then
	# 홈 디렉터리 목록 조회 순서
	# 1. 주석 제외
	# 2. 계정 중에 /bin/false와 nologin을 제외
	# 3. 남은 목록 중에 홈 디렉터리 목록을 조회
	u25homedirs=`cat /etc/passwd | grep -v "^#" | grep -v '/bin/false' | grep -v 'nologin' | awk -F":" 'length($6) > 0 {print $1":"$6}' | sort -u`

	# 점검 파일 목록
	u25envlist=".profile .cshrc .kshrc .login .bash_profile .bashrc .bash_login .exrc .netrc .history .sh_history .bash_history .dtprofile"

	# 소유자가 다르거나 타 사용자 쓰기 권한이 있는 목록 파일
	u25result_1='U25result_1.tmp'
	u25result_2='U25result_2.tmp'
	u25result_3='U25result_3.txt'
	u25result_4='U25result_4.txt'

	#취약한 파일 개수
	u25Count=0

	# 홈 디렉터리 단위로 각각의 점검 파일의 소유자 및 권한 확인
	for dir in $u25homedirs; do
		for file in $u25envlist; do
			# 홈 디렉터리와 점검 파일을 붙여서 경로 생성
			u25checkenv=$(echo $dir | awk -F":" '{print $2}')/$file

			# 홈 디렉터리에 파일이 있는지 확인
			if [ -f $u25checkenv ]; then
				# 홈 디렉터리의 소유자가 실제 소유자와 동일한지 확인
				ls -alL $u25checkenv >> $u25result_3 2>&1
				find $u25checkenv -xdev -perm -2 -exec ls -al {} \; >> $u25result_4 2>&1
				if [ `ls -alL $u25checkenv	| awk '{print $3}'` = `echo $dir | awk -F":" '{print $1}'` ]; then
					# 홈 디렉터리에 other에 쓰기 권한 여부 확인
					if [ `find $u25checkenv -xdev -perm -2 -exec ls -al {} \; | wc -l` -eq 1 ]; then
						# other에 쓰기 권한이 있으므로 취약
						u25Count=$((u25Count + 1))
						ls -alL $u25checkenv >> $u25result_1 2>&1
					fi
				else
					# 소유자가 다르므로 취약
					u25Count=$((u25Count + 1))
					ls -alL $u25checkenv >> $u25result_2 2>&1
				fi
			fi
		done
	done

	if [ $u25Count -gt 0 ]; then
		echo "U-25,X,,"	>> $filepath 2>&1
		echo "사용자의 홈디렉터리 환경변수 파일의 소유자가 타사용자가 이거나 타사용자 쓰기 권한이 있어 취약함" >> $filepath 2>&1
		NewLine $filepath

		if [ -f $u25result_1 ]; then
			echo "other에 쓰기 권한 파일 목록" >> $filepath 2>&1
			cat $u25result_1 >> $filepath 2>&1
			NewLine $filepath
		fi

		if [ -f $u25result_2 ]; then
			echo "소유자가 다른 파일 목록" >> $filepath 2>&1
			cat $u25result_2 >> $filepath 2>&1
		fi
	else
		echo "U-25,O,,"	>> $filepath 2>&1
		echo "사용자의 홈디렉터리 환경변수 파일의 소유자가 타사용자가 아니며 타사용자 쓰기 권한이 제거되어 양호함" >> $filepath 2>&1
        echo "[설정]" >> $filepath 2>&1
		echo "환경변수 파일의 소유자" >> $filepath 2>&1
		cat $u25result_3 >> $filepath 2>&1
		echo "환경변수 파일의 권한" >> $filepath 2>&1
		cat $u25result_4 >> $filepath 2>&1
	fi

	# 파일 정리
	rm -f $u25result_1
	rm -f $u25result_2
	rm -f $u25result_3
	rm -f $u25result_4

else
	echo "U-25,C,,"	>> $filepath 2>&1
	NewLine $filepath
	echo "[수동진단] 담당자 인터뷰 필요-파일 검사 시간 지연(10분 이상)" >> $filepath 2>&1
fi

NewLine $filepath



echo "U-26 Check Start..."
echo "■ U-26. 2. 파일 및 디렉토리 관리 > 2.11 world writable 파일 점검" >> $filepath 2>&1
echo "■ 기준: 불필요한 권한이 부여된 world writable 파일이 존재하지 않을 경우 양호"	>> $filepath 2>&1
echo "■ 현황" >> $filepath 2>&1

U_DATA_26_1='U_DATA_26_1.txt'

if [ $filecheck_pass -eq 0 ]; then
	if [ -d /etc ]; then
	  find /etc -type f -perm -2 -ls | awk '{print $3 " : " $5 " : " $6 " : " $11}' | grep -v "^l"	>> $U_DATA_26_1
	fi

	if [ -d /var ]; then
	  find /var -type f -perm -2 -ls | awk '{print $3 " : " $5 " : " $6 " : " $11}' | grep -v "^l"	>> $U_DATA_26_1
	fi

	if [ -d /tmp ]; then
	  find /tmp -type f -perm -2 -ls | awk '{print $3 " : " $5 " : " $6 " : " $11}' | grep -v "^l"	>> $U_DATA_26_1
	fi

	if [ -d /home ]; then
	  find /home -type f -perm -2 -ls | awk '{print $3 " : " $5 " : " $6 " : " $11}' | grep -v "^l"	>> $U_DATA_26_1
	fi

	if [ -d /export ]; then
	  find /export -type f -perm -2 -ls | awk '{print $3 " : " $5 " : " $6 " : " $11}' | grep -v "^l"	>> $U_DATA_26_1
	fi

	# 3 : 퍼미션
	# 5 : 유저
	# 6 : 그룹
	# 11 : 파일

	# link 파일을 제외하고 전체 경로에서 other에 쓰기 권한이 있는 파일 목록을 검색
	#find / -type f -perm -2 -ls | awk '{print $3 " : " $5 " : " $6 " : " $11}' | grep -v "^l" >> $U_DATA_26_1
	#find / -type f -perm -2 -exec ls -l {} \;	>> $U_DATA_26_1

	if [ -s $U_DATA_26_1 ]; then
		echo "U-26,X,,"	>> $filepath 2>&1
		NewLine $filepath
		echo "World Writable 권한이 부여된 파일이 발견되어 취약함 ( 개수:" `cat $U_DATA_26_1 | wc -l` ")"	>> $filepath 2>&1

		NewLine $filepath
        echo "[설정]" >> $filepath 2>&1
		cat $U_DATA_26_1	>> $filepath 2>&1
	else
		echo "U-26,O,,"	>> $filepath 2>&1
		NewLine $filepath
		echo "World Writable 권한이 부여된 파일이 발견되지 않아 양호함"	>> $filepath 2>&1
	fi

	# 파일 정리
	rm -f $U_DATA_26_1
else
	echo "U-26,C,,"	>> $filepath 2>&1
	NewLine $filepath
	echo "[수동진단] 담당자 인터뷰 필요-파일 검사 시간 지연(10분 이상)"	>> $filepath 2>&1
fi

NewLine $filepath



echo "U-27 Check Start..."
echo "■ U-27. /2. 파일 및 디렉토리 관리 > 2.12 /dev에 존재하지 않는 device 파일 점검" >> $filepath 2>&1
echo "■ 기준: dev 에 존재하지 않은 Device 파일을 점검하고, 존재하지 않은 Device을 제거 했을 경우 양호"	>> $filepath 2>&1
echo "        : (아래 나열된 결과는 major, minor Number를 갖지 않는 파일임)" >> $filepath 2>&1
echo "        : (.devlink_db_lock/.devfsadm_daemon.lock/.devfsadm_synch_door/.devlink_db는 Default로 존재 예외)" >> $filepath 2>&1
echo "■ 현황" >> $filepath 2>&1

u27result='U-27result.tmp'

# /dev 경로에서 파일만 조회
# .udev는 새로운 dev를 관리하기 위한 시스템 파일(Linux Kerner Version 2.6부터 적용됨)
find /dev -type f -exec ls -l {} \;	| grep -v "/dev/.udev/" >> $u27result 2>&1

# 파일 크기가 0보다 크면 취약
if [ -s $u27result ]; then
	echo "U-27,X,,"	>> $filepath 2>&1
	echo "dev 에 존재하지 않은 Device 파일이 발견되어 취약함"	>> $filepath 2>&1
    echo "[설정]" >> $filepath 2>&1
	cat $u27result	>>$filepath 2>&1
else
	echo "U-27,O,,"	>> $filepath 2>&1
	echo "dev 에 존재하지 않은 Device 파일이 발견되지 않아 양호함"	>> $filepath 2>&1
fi

# 파일 정리
rm -f $u27result 

NewLine $filepath



echo "U-28 Check Start..."
echo "■ U-28. 2. 파일 및 디렉토리 관리 > 2.13 $HOME/.rhosts, hosts.equiv 사용 금지" >> $filepath 2>&1
echo "■ 기준: r-commands 서비스를 사용하지 않으면 양호" >> $filepath 2>&1
echo "       : r-commands 서비스를 사용하는 경우 HOME/.rhosts, hosts.equiv 설정확인"	>> $filepath 2>&1
echo "       : (1) .rhosts 파일의 소유자가 해당 계정의 소유자이고, 퍼미션 600, 내용에 + 가 설정되어 있지 않으면 양호"	>> $filepath 2>&1
echo "       : (2) /etc/hosts.equiv 파일의 소유자가 root 이고, 퍼미션 600, 내용에 + 가 설정되어 있지 않으면 양호"	>> $filepath 2>&1
echo "■ 현황" >> $filepath 2>&1

# 점검 파일 목록
u28checkfile='U-28checkfile.tmp'

# 점검 파일 목록에 추가
echo 'root:/etc/hosts.equiv' >> $u28checkfile

# 홈 디렉터리 목록 조회 순서
# 1. 주석 제외
# 2. 계정 중에 /bin/false와 nologin을 제외
# 3. 남은 목록 중에 홈 디렉터리 목록을 조회
u28homedirs=`cat /etc/passwd | grep -v "^#" | grep -v '/bin/false' | grep -v 'nologin' | awk -F":" 'length($6) > 0 {print $1":"$6}' | sort -u`

# 점검 파일 목록에 추가
for dir in $u28homedirs; do
	# 소유자:홈 디렉터리/.rhosts
	u28temp=$(echo $dir)/.rhosts
	echo $u28temp >> $u28checkfile
done

# 소유자가 다르거나 권한이 다르거나 + 설정이 있는 경우
u28result='U-28result.tmp'

for f in `cat $u28checkfile`; do
	u28user=`echo $f | awk -F":" '{print $1}'`
	u28file=`echo $f | awk -F":" '{print $2}'`

	if [ -f $u28file ]; then
		# 홈 디렉터리의 소유자가 실제 소유자와 동일한지 확인
		if [ $u28user = `ls -l $u28file	| awk '{print $3}'` ]; then
			# 퍼미션이 600 이하 확인 (grep으로 group과 other가 -인지 확인)
			if [ `ls -l $u28file | grep "^....------" | wc -l` -eq 0 ]; then
				# 파일 내용에서 +가 포함된 행 수가 0보다 크면 취약
				if [ `cat $u28file | grep "\+" | wc -l` -gt 0 ]; then
					ls -l $u28file >> $u28result 2>&1
				fi
			else
				# 퍼미션이 600을 초과하므로 취약
				ls -l $u28file >> $u28result 2>&1
			fi
		else
			# 소유자가 다르므로 취약
			ls -l $u28file >> $u28result 2>&1
		fi
	fi
done

if [ -s $u28result ]; then
	echo "U-28,X,,"	>> $filepath 2>&1
	echo "소유자/권한/+ 설정에서 문제가 발견되어 취약함"	>> $filepath 2>&1
    echo "[설정]" >> $filepath 2>&1
	cat $u28result >> $FilePath 2>&1
else
	echo "U-28,O,,"	>> $filepath 2>&1
	echo "소유자/권한/+ 설정에서 문제가 없어 양호함"	>> $filepath 2>&1
    echo "[설정]" >> $filepath 2>&1
fi

# /etc/services 파일에서 포트 확인
# 파일에서 1/2 열을 출력 후 tcp가 포함되면 파일에 쓰기
# 변수 양식 : 서비스이름/port/tcp
u28services=`cat /etc/services | awk -F" " '$1=="login" || $1=="shell" || $1=="exec" {print $1 "/" $2}' | grep "tcp"`

u28check='U-28check.tmp'

# 서비스 포트 활성화 여부 확인
for s in $u28services; do
	# 변수에서 port 번호만 추출
	port=`echo $s | awk -F"/" '{print $2}'`

	# 실행 중인 서비스 목록에서 port 번호로 조회
	netstat -na | grep ":$port " | grep -i "^tcp"	>> $u28check
done

# login/shell/exec 서비스 실행 여부를 파일 크기로 확인
if [ -s $u28check ]; then
	echo "r-commands 서비스가 활성화"	>> $filepath 2>&1
	cat $u28check >> $filepath 2>&1
else
	echo "r-commands 서비스가 비활성화"	>> $filepath 2>&1
fi

# 파일 정리
rm -f $u28check
rm -f $u28checkfile
rm -f $u28result

NewLine $filepath



echo "U-29 Check Start..."
echo "■ U-29. 2. 파일 및 디렉토리 관리 > 2.14 접속 IP 및 포트 제한"	>> $filepath 2>&1
echo "■ 기준: 접속을 허용할 특정 호스트에 대한 IP 주소 및 포트 제한을 설정한 경우 양호"	>> $filepath 2>&1
echo "■ 현황"	>> $filepath 2>&1

# 3가지 애플리케이션 확인
# 1. TCP Wrapper
# /etc/hosts.deny 파일에 ALL:ALL로 모두 차단
# 2. IPTables
# chain INPUT 에서 ACCEPT의 정책 확인
# 3. IPFilter
# /etc/ipf/ipf.conf 파일에 정책 확인


if [ -f /etc/hosts.deny ]; then
	if [ `cat /etc/hosts.deny | grep -v "#" | grep -E "ALL:.*ALL" | wc -l` -eq 0 ]; then
		echo "U-29,X,,"	>> $filepath 2>&1
		echo "/etc/hosts.deny 파일에 ALL Deny 설정이 존재하지 않아 취약함" >> $filepath 2>&1
	else
		echo "U-29,O,,"	>> $filepath 2>&1
		echo "/etc/hosts.deny 파일에 ALL Deny 설정이 적용되어 있어 양호함" >> $filepath 2>&1
        echo "[설정]" >> $filepath 2>&1

		ls -l /etc/hosts.deny >> $filepath 2>&1
		cat /etc/hosts.deny | grep -v "#" >> $filepath 2>&1
		ls -l /etc/hosts.allow >> $filepath 2>&1
		cat /etc/hosts.allow | grep -v "#" >> $filepath 2>&1
	fi
else
	echo "U-29,X,,"	>> $filepath 2>&1
	echo "/etc/hosts.deny 파일이 존재하지 않아 취약함" >> $filepath 2>&1
fi

NewLine $filepath



echo "U-30 Check Start..."
echo "■ U-30. 2. 파일 및 디렉토리 관리 > 2.15 hosts.lpd 파일 소유자 및 권한 설정" >> $filepath 2>&1
echo "■ 기준: /etc/host.lpd 파일의 소유자가 root 이고, 권한이 600 이면 양호"	>> $filepath 2>&1
echo "■ 현황" >> $filepath 2>&1

if [ -f /etc/host.lpd ]; then
	test=`ls -alL /etc/host.lpd | awk '{print $3}'`
	if [ $test == 'root' ]; then
		if [ `stat -c %a /etc/host.lpd` -le 600 ]; then
			echo "U-30,O,," >> $filepath 2>&1
			echo "/etc/host.lpd 파일의 소유자가 root이고 파일의 권한이 600보다 낮거나 같아 양호함"	>> $filepath 2>&1
		else
			echo "U-30,X,," >> $filepath 2>&1
			echo "/etc/host.lpd 파일의 소유자가 root이고 파일의 권한이 600보다 높아 취약함"	>> $filepath 2>&1
		fi
	else
		echo "U-30,X,," >> $filepath 2>&1
		echo "/etc/host.lpd 파일의 소유자가 root가 아니므로 취약함"	>> $filepath 2>&1
	fi
    echo "[설정]" >> $filepath 2>&1
	ls -alL /etc/host.lpd	>> $filepath 2>&1
else
	echo "U-30,O,," >> $filepath 2>&1
	echo "/etc/host.lpd 파일이 없어 양호함"	>> $filepath 2>&1
fi

NewLine $filepath



echo "U-31 Check Start..."
echo "■ U-31. 2. 파일 및 디렉토리 관리 > 2.16 UMASK 설정 관리" >> $filepath 2>&1
echo "■ 기준: UMASK 값이 022 이면 양호" >> $filepath 2>&1
echo "       : (1) sh, ksh, bash 쉘의 경우 /etc/profile 파일 설정을 적용받음"	>> $filepath 2>&1
echo "       : (2) csh, tcsh 쉘의 경우 /etc/csh.cshrc 또는 /etc/csh.login 파일 설정을 적용받음" >> $filepath 2>&1
echo "■ 현황" >> $filepath 2>&1

echo "U-31,C,,"	>> $filepath 2>&1
NewLine $filepath
echo "[설정]" >> $filepath 2>&1
echo "현재 로그인 계정 UMASK"	>> $filepath 2>&1
DividingLine $filepath
umask	>> $filepath 2>&1

if [ -f /etc/profile ]; then
	echo "① /etc/profile 파일(올바른 설정: umask 022)"	>> $filepath 2>&1
	DividingLine $filepath
	if [ `cat /etc/profile | grep -i umask | grep -v ^# | wc -l` -gt 0 ]; then
		cat /etc/profile | grep -i umask | grep -v ^#	>> $filepath 2>&1
	else
		echo "umask 설정이 없음"	>> $filepath 2>&1
	fi
else
	echo "/etc/profile 파일이 없음"	>> $filepath 2>&1
fi

NewLine $filepath

if [ -f /etc/csh.login ]; then
	echo "② /etc/csh.login 파일"	>> $filepath 2>&1
	DividingLine $filepath

	if [ `cat /etc/csh.login | grep -i umask | grep -v ^# | wc -l` -gt 0 ]; then
		cat /etc/csh.login | grep -i umask | grep -v ^#	>> $filepath 2>&1
	else
		echo "umask 설정이 없음"	>> $filepath 2>&1
	fi
else
	echo "/etc/csh.login 파일이 없음"	>> $filepath 2>&1
fi

NewLine $filepath

if [ -f /etc/csh.login ]; then
	echo "③ /etc/csh.cshrc 파일"	>> $filepath 2>&1
	DividingLine $filepath

	if [ `cat /etc/csh.cshrc | grep -i umask | grep -v ^# | wc -l` -gt 0 ]; then
		cat /etc/csh.cshrc | grep -i umask | grep -v ^#	>> $filepath 2>&1
	else
		echo "umask 설정이 없음"	>> $filepath 2>&1
	fi
else
	echo "/etc/csh.cshrc 파일이 없음"	>> $filepath 2>&1
fi

NewLine $filepath


echo "U-32 Check Start..."
echo "■ U-32. 2. 파일 및 디렉토리 관리 > 2.17 홈 디렉터리 소유자 및 권한 설정" >> $filepath 2>&1
echo "■ 기준: 홈 디렉터리의 소유자가 /etc/passwd 내에 등록된 홈 디렉터리 사용자와 일치하고, 홈 디렉터리에 타사용자 쓰기권한이 없으면 양호"	>> $filepath 2>&1
echo "■ 현황" >> $filepath 2>&1

echo "U-32,C,,"	>> $filepath 2>&1
NewLine $filepath
echo "[설정]" >> $filepath 2>&1
echo "사용자 홈 디렉터리"	>> $filepath 2>&1
DividingLine $filepath

HOMEDIRS=`cat /etc/passwd | awk -F":" 'length($6) > 0 {print $6}' | sort -u | grep -v "#" | grep -v "/tmp" | grep -v "uucppublic" | uniq`

for dir in $HOMEDIRS; do
	if [ -d $dir ]; then
		ls -dal $dir | grep '\d.........'	>> $filepath 2>&1
	fi
done

NewLine $filepath


echo "U-33 Check Start..."
echo "■ U-33. 2. 파일 및 디렉토리 관리 > 2.18 홈 디렉터리로 지정한 디렉터리의 존재 관리" >> $filepath 2>&1
echo "■ 기준: 홈 디렉터리가 존재하지 않는 계정이 발견되지 않으면 양호"	>> $filepath 2>&1
# 홈 디렉터리가 존재하지 않는 경우, 일반 사용자가 로그인을 하면 사용자의 현재 디렉터리가 /로 로그인 되므로 관리,보안상 문제가 발생됨.
# 예) 해당 계정으로 ftp 로그인 시 / 디렉터리로 접속하여 중요 정보가 노출될 수 있음.
echo "■ 현황" >> $filepath 2>&1

# /var 시스템 운용 중에 일시적으로 저장하기 위한 디렉터리
HOMEDIRS=`cat /etc/passwd | awk -F":" 'length($6) > 0 {print $6}' | sort -u | grep -v "#" | grep -v "/tmp" | grep -v "/var" | grep -v "uucppublic" | uniq`

# 디렉터리가 실제로 존재하는지 확인
U_58_Count=0
for dir in $HOMEDIRS; do
	if [ ! -d $dir ]; then
		U_58_Count=$((U_58_Count + 1))
	fi
done

#NewLine $filepath

if [ $U_58_Count -gt 0 ]; then
	echo "U-33,X,,"	>> $filepath 2>&1
	echo "홈 디렉터리가 존재하지 않은 계정이 발견되어 취약함" >> $filepath 2>&1
    echo "[설정]" >> $filepath 2>&1

	NewLine $filepath

	echo "계정명(홈디렉터리)" >> $filepath 2>&1
	for dir in $HOMEDIRS; do
		if [ ! -d $dir ]; then
			awk -F: '$6=="'${dir}'" { print $1 "(" $6 ")" }' /etc/passwd	>> $filepath 2>&1
		fi
	done
else
	echo "U-33,O,,"	>> $filepath 2>&1
	echo "홈 디렉터리가 존재하지 않은 계정이 발견되지 않아 양호함"	>> $filepath 2>&1
fi

NewLine $filepath


echo "U-34 Check Start..."
echo "■ U-34. 2. 파일 및 디렉토리 관리 > 2.19 숨겨진 파일 및 디렉터리 검색 및 제거" >> $filepath 2>&1
echo "■ 기준: 디렉터리 내에 숨겨진 파일을 확인 및 검색하여 불필요한 파일 존재 경우 삭제 했을 경우 양호"	>> $filepath 2>&1
echo "■ 현황" >> $filepath 2>&1

if [ $filecheck_pass -eq 0 ]; then
	A=`find /tmp -name ".*" | wc -l`
	if [ $A -gt 0 ]; then
		echo "U-34,X,,"	>> $filepath 2>&1
		NewLine $filepath
		echo "디렉터리 내 숨겨진 파일을 확인하지 않고, 불필요한 파일이 존재해 취약함"	>> $filepath 2>&1
	else
		echo "U-34,O,,"	>> $filepath 2>&1
		NewLine $filepath
		echo "디렉터리 내 숨겨진 파일을 확인하여, 불필요한 파일 삭제하여 양호함"	>> $filepath 2>&1
	fi

	NewLine $filepath
	echo "[설정]" >> $filepath 2>&1
	find /tmp -name ".*" -ls	>> $filepath 2>&1
	find /home -name ".*" -ls	>> $filepath 2>&1
	find /usr -name ".*" -ls	>> $filepath 2>&1
	find /var -name ".*" -ls	>> $filepath 2>&1
	echo "위에 리스트에서 숨겨진 파일 확인"	>> $filepath 2>&1
else
	echo "U-34,C,,"	>> $filepath 2>&1
	NewLine $filepath
	echo "[수동진단] 담당자 인터뷰 필요-파일 검사 시간 지연(10분 이상)"	>> $filepath 2>&1
fi

NewLine $filepath


echo "U-35 Check Start..."
echo "■ U-35. 3. 서비스 관리 > 3.1 Finger 서비스 비활성화" >> $filepath 2>&1
echo "■ 기준: Finger 서비스가 비활성화 되어 있을 경우 양호"	>> $filepath 2>&1
echo "■ 현황" >> $filepath 2>&1

if [ `cat /etc/services | awk -F" " '$1=="finger" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]; then
	port=`cat /etc/services | awk -F" " '$1=="finger" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`
	if [ `netstat -na | grep ":$port " | grep -i "^tcp" | wc -l` -eq 0 ]; then
		echo "U-35,O,,"	>> $filepath 2>&1
		echo "Finger 서비스가 비활성화 되어 있어 양호함"	>> $filepath 2>&1
	else
		echo "U-35,X,,"	>> $filepath 2>&1
		echo "Finger 서비스가 활성화 되어 있어 취약함"	>> $filepath 2>&1
	fi
else
	if [ `netstat -na | grep ":79 " | grep -i "^tcp" | wc -l` -eq 0 ]; then
		echo "U-35,O,,"	>> $filepath 2>&1
		echo "Finger 서비스가 비활성화 되어 있어 양호함"	>> $filepath 2>&1
	else
		echo "U-35,X,,"	>> $filepath 2>&1
		echo "Finger 서비스가 활성화 되어 있어 취약함"	>> $filepath 2>&1
	fi
fi
echo "[설정]" >> $filepath 2>&1
NewLine $filepath
echo "① /etc/services 파일에서 포트 확인"	>> $filepath 2>&1
DividingLine $filepath

cat /etc/services | awk -F" " '$1=="finger" {print $1 "   " $2}' | grep "tcp"	>> $filepath 2>&1
NewLine $filepath
echo "② 서비스 포트 활성화 여부 확인"	>> $filepath 2>&1
DividingLine $filepath

if [ `cat /etc/services | awk -F" " '$1=="finger" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]; then
	port=`cat /etc/services | awk -F" " '$1=="finger" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`
	if [ `netstat -na | grep ":$port " | grep -i "^tcp" | wc -l` -eq 0 ]; then
		NewLine $filepath
	else
		netstat -na | grep ":$port " | grep -i "^tcp"	>> $filepath 2>&1
	fi
else
	if [ `netstat -na | grep ":79 " | grep -i "^tcp" | wc -l` -eq 0 ]; then
		NewLine $filepath
	else
		netstat -na | grep ":79 " | grep -i "^tcp"	>> $filepath 2>&1
	fi
fi

NewLine $filepath



echo "U-36 Check Start..."
echo "■ U-36. 3. 서비스 관리 > 3.2 Anonymous FTP 비활성화" >> $filepath 2>&1
echo "■ 기준: Anonymous FTP (익명 ftp)를 비활성화 시켰을 경우 양호"	>> $filepath 2>&1
echo "(1)ftpd를 사용할 경우: /etc/passwd 파일내 FTP 또는 anonymous 계정이 존재하지 않으면 양호"	>> $filepath 2>&1
echo "(2)proftpd를 사용할 경우: /etc/passwd 파일내 FTP 계정이 존재하지 않으면 양호" >> $filepath 2>&1
echo "(3)vsftpd를 사용할 경우: vsftpd.conf 파일에서 anonymous_enable=NO 설정이면 양호" >> $filepath 2>&1
echo "■ 현황" >> $filepath 2>&1


echo "U-36,C,,"	>> $filepath 2>&1
NewLine $filepath
echo "[설정]" >> $filepath 2>&1
echo "① /etc/services 파일에서 포트 확인"	>> $filepath 2>&1
DividingLine $filepath

if [ `cat /etc/services | awk -F" " '$1=="ftp" {print "(1)/etc/service파일:" $1 " " $2}' | grep "tcp" | wc -l` -gt 0 ]; then
	cat /etc/services | awk -F" " '$1=="ftp" {print "(1)/etc/service파일:" $1 " " $2}' | grep "tcp" >> $filepath 2>&1
else
	echo "(1)/etc/service파일: 포트 설정 X (Default 21번 포트)"	>> $filepath 2>&1
fi

if [ -s vsftpd.txt ]; then
	if [ `cat $vsfile | grep "listen_port" | grep -v "^#" | awk '{print "(3)VsFTP 포트: " $1 "  " $2}' | wc -l` -gt 0 ]; then
		cat $vsfile | grep "listen_port" | grep -v "^#" | awk '{print "(3)VsFTP 포트: " $1 "  " $2}' >> $filepath 2>&1
	else
		echo "(2)VsFTP 포트: 포트 설정 X (Default 21번 포트 사용중)"	>> $filepath 2>&1
	fi
else
	echo "(2)VsFTP 포트: VsFTP가 설치되어 있지 않음"	>> $filepath 2>&1
fi

if [ -s proftpd.txt ]; then
	if [ `cat $profile | grep "Port" | grep -v "^#" | awk '{print "(2)ProFTP 포트: " $1 "  " $2}' | wc -l` -gt 0 ]; then
		cat $profile | grep "Port" | grep -v "^#" | awk '{print "(2)ProFTP 포트: " $1 "  " $2}'    >> $filepath 2>&1
	else
		echo "(3)ProFTP 포트: 포트 설정 X (/etc/service 파일에 설정된 포트를 사용중)"	>> $filepath 2>&1
	fi
else
	echo "(3)ProFTP 포트: ProFTP가 설치되어 있지 않음"	>> $filepath 2>&1
fi

NewLine $filepath
echo "② 서비스 포트 활성화 여부 확인"	>> $filepath 2>&1
DividingLine $filepath
################# /etc/services 파일에서 포트 확인 #################
if [ `cat /etc/services | awk -F" " '$1=="ftp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]; then
	port=`cat /etc/services | awk -F" " '$1=="ftp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`

	if [ `netstat -nat | grep ":$port " | grep -i "^tcp" | grep -i "LISTEN" | wc -l` -gt 0 ]; then
		netstat -nat | grep ":$port " | grep -i "^tcp" | grep -i "LISTEN"	>> $filepath 2>&1
		NewLine ftpenable.txt
	fi
else
	netstat -nat | grep ":21 " | grep -i "^tcp" | grep -i "LISTEN"	>> $filepath 2>&1
	NewLine ftpenable.txt
fi

################# vsftpd 에서 포트 확인 ############################
if [ -s vsftpd.txt ]; then
	if [ `cat $vsfile | grep "listen_port" | grep -v "^#" | awk -F"=" '{print $2}' | wc -l` -eq 0 ]; then
		port=21
	else
		port=`cat $vsfile | grep "listen_port" | grep -v "^#" | awk -F"=" '{print $2}'`
	fi

	if [ `netstat -nat | grep ":$port " | grep -i "^tcp" | grep -i "LISTEN" | wc -l` -gt 0 ]; then
		netstat -nat | grep ":$port " | grep -i "^tcp" | grep -i "LISTEN"	>> $filepath 2>&1
		NewLine ftpenable.txt
	fi
fi

################# proftpd 에서 포트 확인 ###########################
if [ -s proftpd.txt ]; then
	port=`cat $profile | grep "Port" | grep -v "^#" | awk '{print $2}'`

	if [ `netstat -nat | grep ":$port " | grep -i "^tcp" | grep -i "LISTEN" | wc -l` -gt 0 ]; then
		netstat -nat | grep ":$port " | grep -i "^tcp" | grep -i "LISTEN"	>> $filepath 2>&1
		NewLine ftpenable.txt
	fi
fi

if [ -f ftpenable.txt ]; then
	rm -f ftpenable.txt
else
	echo "FTP Service Disable"	>> $filepath 2>&1
fi

NewLine $filepath
echo "③ Anonymous FTP 설정 확인"	>> $filepath 2>&1
DividingLine $filepath

if [ -s vsftpd.txt ]; then
	cat $vsfile | grep -i "anonymous_enable" | awk '{print "● VsFTP 설정: " $0}'	>> $filepath 2>&1
fi

if [ `cat /etc/passwd | egrep "^ftp:|^anonymous:" | wc -l` -gt 0 ]; then
	echo "● ProFTP, 기본FTP 설정:"	>> $filepath 2>&1
	cat /etc/passwd | egrep "^ftp:|^anonymous:"	>> $filepath 2>&1
	NewLine $filepath
else
	echo "● ProFTP, 기본FTP 설정: /etc/passwd 파일에 ftp 또는 anonymous 계정이 없음"	>> $filepath 2>&1
fi

NewLine $filepath



echo "U-37 Check Start..."
echo "■ U-37. 3. 서비스 관리 > 3.3 r 계열 서비스 비활성화" >> $filepath 2>&1
echo "■ 기준: r-commands 서비스를 사용하지 않으면 양호"	>> $filepath 2>&1
echo "■ 현황" >> $filepath 2>&1

if [ `cat /etc/services | awk -F" " '$1=="login" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]; then
	port=`cat /etc/services | awk -F" " '$1=="login" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`
	if [ `netstat -na | grep ":$port " | grep -i "^tcp" | wc -l` -gt 0 ]; then
		NewLine rcommand.txt
	fi
fi

if [ `cat /etc/services | awk -F" " '$1=="shell" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]; then
	port=`cat /etc/services | awk -F" " '$1=="shell" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`

	if [ `netstat -na | grep ":$port " | grep -i "^tcp" | wc -l` -gt 0 ]; then
		NewLine rcommand.txt
	fi
fi

if [ `cat /etc/services | awk -F" " '$1=="exec" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]; then
	port=`cat /etc/services | awk -F" " '$1=="exec" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`

	if [ `netstat -na | grep ":$port " | grep -i "^tcp" | wc -l` -gt 0 ]; then
		NewLine rcommand.txt
	fi
fi

if [ -f rcommand.txt ]; then
	rm -f rcommand.txt
	echo "U-37,X,," >> $filepath 2>&1
	echo "r 계열 서비스가 활성화 되어 있어 취약함" >> $filepath 2>&1
else
	echo "U-37,O,," >> $filepath 2>&1
	echo "r 계열 서비스가 비활성화 되어 있어 양호함"	>> $filepath 2>&1
fi

echo "[설정]" >> $filepath 2>&1
echo "① /etc/services 파일에서 포트 확인"	>> $filepath 2>&1
DividingLine $filepath

cat /etc/services | awk -F" " '$1=="login" {print $1 "   " $2}' | grep "tcp"	>> $filepath 2>&1
cat /etc/services | awk -F" " '$1=="shell" {print $1 "   " $2}' | grep "tcp"	>> $filepath 2>&1
cat /etc/services | awk -F" " '$1=="exec" {print $1 "    " $2}' | grep "tcp"	>> $filepath 2>&1

NewLine $filepath
echo "② 서비스 포트 활성화 여부 확인(서비스 중지시 결과 값 없음)"	>> $filepath 2>&1
DividingLine $filepath

if [ `cat /etc/services | awk -F" " '$1=="login" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]; then
	port=`cat /etc/services | awk -F" " '$1=="login" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`
	if [ `netstat -na | grep ":$port " | grep -i "^tcp" | wc -l` -gt 0 ]; then
		netstat -na | grep ":$port " | grep -i "^tcp"	>> $filepath 2>&1
	fi
fi

if [ `cat /etc/services | awk -F" " '$1=="shell" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]; then
	port=`cat /etc/services | awk -F" " '$1=="shell" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`
	if [ `netstat -na | grep ":$port " | grep -i "^tcp" | wc -l` -gt 0 ]; then
		netstat -na | grep ":$port " | grep -i "^tcp"	>> $filepath 2>&1
	fi
fi

if [ `cat /etc/services | awk -F" " '$1=="exec" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]; then
	port=`cat /etc/services | awk -F" " '$1=="exec" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`
	if [ `netstat -na | grep ":$port " | grep -i "^tcp" | wc -l` -gt 0 ]; then
		netstat -na | grep ":$port " | grep -i "^tcp"	>> $filepath 2>&1
	fi
fi

NewLine $filepath


echo "U-38 Check Start..."
echo "■ U-38. 3. 서비스 관리 > 3.4 cron 파일 소유자 및 권한 설정" >> $filepath 2>&1
echo "■ 기준: cron.allow 또는 cron.deny 파일 권한이 640 이하이면 양호"	>> $filepath 2>&1
echo "■ 현황" >> $filepath 2>&1

# 1 : 파일이 없음
# 2 : 파일 권한 양호
# 3 : 파일 권한 취약
U22_ALLOW=0
U22_DENY=0

if [ -f /etc/cron.allow ]; then
	if [ `stat -c %a /etc/cron.allow` -le 640 ]; then
		U22_ALLOW=2
	else
		U22_ALLOW=3
	fi
else
	U22_ALLOW=1
fi

if [ -f /etc/cron.deny ]; then
	if [ `stat -c %a /etc/cron.deny` -le 640 ]; then
		U22_DENY=2
	else
		U22_DENY=3
	fi
else
	U22_DENY=1
fi

if [ $U22_ALLOW -eq 1 -a $U22_DENY -eq 1 ]; then
	echo "U-38,O,," >> $filepath 2>&1
	echo "cron.allow와 cron.deny 파일이 없어 양호함"	>> $filepath 2>&1
elif [ $U22_ALLOW -eq 3 -o $U22_DENY -eq 3 ]; then
	echo "U-38,X,," >> $filepath 2>&1
	echo "cron.allow 또는 cron.deny 파일이 권한이 640보다 높아 취약함"	>> $filepath 2>&1
else
	echo "U-38,O,," >> $filepath 2>&1
	echo "cron.allow와 cron.deny 파일의 권한이 640보다 낮거나 같아 양호함"	>> $filepath 2>&1
fi
echo "[설정]" >> $filepath 2>&1
if [ $U22_ALLOW -ne 1 ]; then
	ls -l /etc/cron.allow	>> $filepath 2>&1
fi

if [ $U22_DENY -ne 1 ]; then
	ls -l /etc/cron.deny	>> $filepath 2>&1
fi

NewLine $filepath



echo "U-39 Check Start..."
echo "■ U-39. 3. 서비스 관리 > 3.5 DoS 공격에 취약한 서비스 비활성화" >> $filepath 2>&1
echo "■ 기준: DoS 공격에 취약한 echo, discard, daytime, chargen 서비스를 사용하지 않았을 경우 양호"	>> $filepath 2>&1
echo "■ 현황" >> $filepath 2>&1

if [ `cat /etc/services | awk -F" " '$1=="echo" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]; then
	port=`cat /etc/services | awk -F" " '$1=="echo" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`
	if [ `netstat -na | grep ":$port " | grep -i "^tcp" | wc -l` -gt 0 ]; then
		NewLine unnecessary.txt
	fi
fi

if [ `cat /etc/services | awk -F" " '$1=="echo" {print $1 "   " $2}' | grep "udp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]; then
	port=`cat /etc/services | awk -F" " '$1=="echo" {print $1 "   " $2}' | grep "udp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`
	if [ `netstat -na | grep ":$port " | grep -i "^udp" | wc -l` -gt 0 ]; then
		NewLine unnecessary.txt
	fi
fi

if [ `cat /etc/services | awk -F" " '$1=="discard" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]; then
	port=`cat /etc/services | awk -F" " '$1=="discard" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`
	if [ `netstat -na | grep ":$port " | grep -i "^tcp" | wc -l` -gt 0 ]; then
		NewLine unnecessary.txt
	fi
fi

if [ `cat /etc/services | awk -F" " '$1=="discard" {print $1 "   " $2}' | grep "udp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]; then
	port=`cat /etc/services | awk -F" " '$1=="discard" {print $1 "   " $2}' | grep "udp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`
	if [ `netstat -na | grep ":$port " | grep -i "^udp" | wc -l` -gt 0 ]; then
		NewLine unnecessary.txt
	fi
fi

if [ `cat /etc/services | awk -F" " '$1=="daytime" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]; then
	port=`cat /etc/services | awk -F" " '$1=="daytime" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`
	if [ `netstat -na | grep ":$port " | grep -i "^tcp" | wc -l` -gt 0 ]; then
		NewLine unnecessary.txt
	fi
fi

if [ `cat /etc/services | awk -F" " '$1=="daytime" {print $1 "   " $2}' | grep "udp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]; then
	port=`cat /etc/services | awk -F" " '$1=="daytime" {print $1 "   " $2}' | grep "udp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`
	if [ `netstat -na | grep ":$port " | grep -i "^udp" | wc -l` -gt 0 ]; then
		NewLine unnecessary.txt
	fi
fi

if [ `cat /etc/services | awk -F" " '$1=="chargen" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]; then
	port=`cat /etc/services | awk -F" " '$1=="chargen" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`
	if [ `netstat -na | grep ":$port " | grep -i "^tcp" | wc -l` -gt 0 ]; then
		NewLine unnecessary.txt
	fi
fi

if [ `cat /etc/services | awk -F" " '$1=="chargen" {print $1 "   " $2}' | grep "udp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]; then
	port=`cat /etc/services | awk -F" " '$1=="chargen" {print $1 "   " $2}' | grep "udp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`
	if [ `netstat -na | grep ":$port " | grep -i "^udp" | wc -l` -gt 0 ]; then
		NewLine unnecessary.txt
	fi
fi

if [ -f unnecessary.txt ]; then
	rm -f unnecessary.txt
	echo "U-39,X,," >> $filepath 2>&1
	echo "Dos 공격에 취약한 echo, discard, daytime, chargen 서비스가 활성화 되어 취약함"	>> $filepath 2>&1
else
	echo "U-39,O,," >> $filepath 2>&1
	echo "Dos 공격에 취약한 echo, discard, daytime, chargen 서비스가 비활성화 되어 양호함"	>> $filepath 2>&1
fi
echo "[설정]" >> $filepath 2>&1
echo "① /etc/services 파일에서 포트 확인"	>> $filepath 2>&1
DividingLine $filepath

cat /etc/services | awk -F" " '$1=="echo" {print $1 "      " $2}' | grep "tcp"	>> $filepath 2>&1
cat /etc/services | awk -F" " '$1=="echo" {print $1 "      " $2}' | grep "udp"	>> $filepath 2>&1
cat /etc/services | awk -F" " '$1=="discard" {print $1 "   " $2}' | grep "tcp"	>> $filepath 2>&1
cat /etc/services | awk -F" " '$1=="discard" {print $1 "   " $2}' | grep "udp"	>> $filepath 2>&1
cat /etc/services | awk -F" " '$1=="daytime" {print $1 "   " $2}' | grep "tcp"	>> $filepath 2>&1
cat /etc/services | awk -F" " '$1=="daytime" {print $1 "   " $2}' | grep "udp"	>> $filepath 2>&1
cat /etc/services | awk -F" " '$1=="chargen" {print $1 "   " $2}' | grep "tcp"	>> $filepath 2>&1
cat /etc/services | awk -F" " '$1=="chargen" {print $1 "   " $2}' | grep "udp"	>> $filepath 2>&1

NewLine $filepath
echo "② 서비스 포트 활성화 여부 확인"	>> $filepath 2>&1
DividingLine $filepath

if [ `cat /etc/services | awk -F" " '$1=="echo" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]; then
	port=`cat /etc/services | awk -F" " '$1=="echo" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`

	if [ `netstat -na | grep ":$port " | grep -i "^tcp" | wc -l` -gt 0 ]; then
		netstat -na | grep ":$port " | grep -i "^tcp"	>> $filepath 2>&1
	fi
fi

if [ `cat /etc/services | awk -F" " '$1=="echo" {print $1 "   " $2}' | grep "udp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]; then
	port=`cat /etc/services | awk -F" " '$1=="echo" {print $1 "   " $2}' | grep "udp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`

	if [ `netstat -na | grep ":$port " | grep -i "^udp" | wc -l` -gt 0 ]; then
		netstat -na | grep ":$port " | grep -i "^udp"	>> $filepath 2>&1
	fi
fi

if [ `cat /etc/services | awk -F" " '$1=="discard" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]; then
	port=`cat /etc/services | awk -F" " '$1=="discard" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`

	if [ `netstat -na | grep ":$port " | grep -i "^tcp" | wc -l` -gt 0 ]; then
		netstat -na | grep ":$port " | grep -i "^tcp"	>> $filepath 2>&1
	fi
fi

if [ `cat /etc/services | awk -F" " '$1=="discard" {print $1 "   " $2}' | grep "udp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]; then
	port=`cat /etc/services | awk -F" " '$1=="discard" {print $1 "   " $2}' | grep "udp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`

	if [ `netstat -na | grep ":$port " | grep -i "^udp" | wc -l` -gt 0 ]; then
		netstat -na | grep ":$port " | grep -i "^udp"	>> $filepath 2>&1
	fi
fi

if [ `cat /etc/services | awk -F" " '$1=="daytime" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]; then
	port=`cat /etc/services | awk -F" " '$1=="daytime" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`

	if [ `netstat -na | grep ":$port " | grep -i "^tcp" | wc -l` -gt 0 ]; then
		netstat -na | grep ":$port " | grep -i "^tcp"	>> $filepath 2>&1
	fi
fi

if [ `cat /etc/services | awk -F" " '$1=="daytime" {print $1 "   " $2}' | grep "udp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]; then
	port=`cat /etc/services | awk -F" " '$1=="daytime" {print $1 "   " $2}' | grep "udp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`

	if [ `netstat -na | grep ":$port " | grep -i "^udp" | wc -l` -gt 0 ]; then
		netstat -na | grep ":$port " | grep -i "^udp"	>> $filepath 2>&1
	fi
fi

if [ `cat /etc/services | awk -F" " '$1=="chargen" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]; then
	port=`cat /etc/services | awk -F" " '$1=="chargen" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`

	if [ `netstat -na | grep ":$port " | grep -i "^tcp" | wc -l` -gt 0 ]; then
		netstat -na | grep ":$port " | grep -i "^tcp"	>> $filepath 2>&1
	fi
fi

if [ `cat /etc/services | awk -F" " '$1=="chargen" {print $1 "   " $2}' | grep "udp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]; then
	port=`cat /etc/services | awk -F" " '$1=="chargen" {print $1 "   " $2}' | grep "udp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`

	if [ `netstat -na | grep ":$port " | grep -i "^udp" | wc -l` -gt 0 ]; then
		netstat -na | grep ":$port " | grep -i "^udp"	>> $filepath 2>&1
	fi
fi

NewLine $filepath



echo "U-40 Check Start..."
echo "■ U-40. 3. 서비스 관리 > 3.6 NFS 서비스 비활성화" 		>> $filepath 2>&1
echo "■ 기준: 불필요한 NFS 서비스 관련 데몬이 제거되어 있는 경우 양호"	>> $filepath 2>&1
echo "■ 현황" >> $filepath 2>&1

if [ `ps -ef | grep "nfsd" | egrep -v "statdaemon|automountd|emi" | grep -v "grep" | wc -l` -gt 0 ]; then
	echo "U-40,X,,"	>> $filepath 2>&1
	echo "NFS 서비스 관련 데몬이 활성화 되어 있어 취약함"	>> $filepath 2>&1
	echo "NFS Server Daemon(nfsd)확인"	>> $filepath 2>&1
	echo "[설정]" >> $filepath 2>&1
	ps -ef | grep "nfsd" | egrep -v "statdaemon|automountd|emi" | grep -v "grep"	>> $filepath 2>&1
else
	if [ `ps -ef | egrep "statd|lockd" | egrep -v "grep|emi|statdaemon|dsvclockd|kblockd" | wc -l` -gt 0 ]; then
		echo "U-40,X,,"	>> $filepath 2>&1
		echo "NFS 서비스 관련 데몬이 활성화 되어 있어 취약함"	>> $filepath 2>&1
		echo "NFS Client Daemon(statd,lockd)확인"	>> $filepath 2>&1
		echo "[설정]" >> $filepath 2>&1
		ps -ef | egrep "statd|lockd" | egrep -v "grep|emi|statdaemon|dsvclockd|kblockd"	>> $filepath 2>&1
	else
		echo "U-40,O,,"	>> $filepath 2>&1
		echo "NFS 서비스 관련 데몬이 비활성화 되어 있어 양호함"	>> $filepath 2>&1
	fi
fi

NewLine $filepath


echo "U-41 Check Start..."
echo "■ U-41. 3. 서비스 관리 > 3.7 NFS 접근통제" >> $filepath 2>&1
echo "■ 기준: NFS 서버 데몬이 동작하지 않으면 양호"	>> $filepath 2>&1
echo "■ 기준: NFS 서버 데몬이 동작하는 경우 /etc/exports 파일에 everyone 공유 설정이 없으면 양호"	>> $filepath 2>&1
echo "■ 현황" >> $filepath 2>&1

# (취약 예문) /tmp/test/share *(rw)
if [ `ps -ef | grep "nfsd" | egrep -v "statdaemon|automountd|emi" | grep -v "grep" | wc -l` -gt 0 ]; then
	echo "U-41,C,,"	>> $filepath 2>&1
	echo "[설정]" >> $filepath 2>&1
	echo "① NFS Server Daemon(nfsd)확인"	>> $filepath 2>&1
	DividingLine $filepath

	ps -ef | grep "nfsd" | egrep -v "statdaemon|automountd|emi" | grep -v "grep"	>> $filepath 2>&1

	if [ -f /etc/exports ]; then
		if [ `cat /etc/exports | grep -v "^#" | grep -v "^ *$" | wc -l` -gt 0 ]; then
			echo "NFS 서버 데몬이 동작하는 경우 /etc/exports 파일에 everyone 공유 설정이 있음"	>> $filepath 2>&1
			echo "② /etc/exports 파일 설정"	>> $filepath 2>&1
			DividingLine $filepath

			cat /etc/exports | grep -v "^#" | grep -v "^ *$"	>> $filepath 2>&1
		else
			echo "NFS 서버 데몬이 동작하는 경우 /etc/exports 파일에 everyone 공유 설정이 없음"	>> $filepath 2>&1
		fi
	else
		echo "/etc/exports 파일이 없음"	>> $filepath 2>&1
	fi
 else
	echo "U-41,O,,"	>> $filepath 2>&1
	echo "NFS 서버 데몬이 동작하지 않아 양호함"	>> $filepath 2>&1
fi

NewLine $filepath


echo "U-42 Check Start..."
echo "■ U-42. 3. 서비스 관리 > 3.8 automountd 제거" >> $filepath 2>&1
echo "■ 기준: automountd 서비스가 동작하지 않을 경우 양호"	>> $filepath 2>&1
echo "■ 현황" >> $filepath 2>&1

# automount 서비스를 찾기 위해 automount 또는 autofs로 검색
# 목록 중에 grep, statdaemon, emi 제외하고 출력
if [ `ps -ef | egrep 'automount|autofs' | grep -v "grep" | egrep -v "statdaemon|emi" | wc -l` -gt 0 ]; then
	echo "U-42,X,,"	>> $filepath 2>&1
	echo "automountd 서비스가 활성화 되어 있어 취약함"	>> $filepath 2>&1
else
	echo "U-42,O,,"	>> $filepath 2>&1
	echo "automountd 서비스가 비활성화 되어 있어 양호함"	>> $filepath 2>&1
fi
echo "[설정]" >> $filepath 2>&1
echo "① Automountd Daemon 확인"	>> $filepath 2>&1
DividingLine $filepath

ps -ef | egrep 'automount|autofs' | grep -v "grep" | egrep -v "statdaemon|emi"	>> $filepath 2>&1

NewLine $filepath


echo "U-43 Check Start..."
echo "■ U-43. 3. 서비스 관리 > 3.9 RPC 서비스 확인" >> $filepath 2>&1
echo "■ 기준: 불필요한 rpc 관련 서비스가 존재하지 않으면 양호"	>> $filepath 2>&1
echo "(rpc.cmsd|rpc.ttdbserverd|sadmind|rusersd|walld|sprayd|rstatd|rpc.nisd|rpc.pcnfsd|rpc.statd|rpc.ypupdated|rpc.rquotad|kcms_server|cachefsd|rexd)" >> $filepath 2>&1
echo "■ 현황" >> $filepath 2>&1

SERVICE_INETD="rpc.cmsd|rpc.ttdbserverd|sadmind|rusersd|walld|sprayd|rstatd|rpc.nisd|rpc.pcnfsd|rpc.statd|rpc.ypupdated|rpc.rquotad|kcms_server|cachefsd|rexd"

if [ -d /etc/xinetd.d ]; then
	if [ `ls -alL /etc/xinetd.d/* | egrep $SERVICE_INETD | wc -l` -eq 0 ]; then
		echo "U-43,O,,"	>> $filepath 2>&1
		echo "불필요한 RPC 서비스가 비활성화 되어있어 양호함"	>> $filepath 2>&1
	else
		echo "U-43,X,,"	>> $filepath 2>&1
		echo "불필요한 RPC 서비스가 활성화 되어있어 취약함"	>> $filepath 2>&1
		echo "불필요한 RPC 서비스 동작 확인"	>> $filepath 2>&1
		DividingLine $filepath
	fi
		echo "[설정]" >> $filepath 2>&1
		ls -alL /etc/xinetd.d/* | egrep $SERVICE_INETD	>> $filepath 2>&1
else
	echo "U-43,O,,"	>> $filepath 2>&1
	echo "/etc/xinetd.d 디렉터리가 존재하지 않아 양호함"	>> $filepath 2>&1
fi

NewLine $filepath



echo "U-44 Check Start..."
echo "■ U-44. 3. 서비스 관리 > 3.10 NIS , NIS+ 점검" >> $filepath 2>&1
echo "■ 기준: NIS, NIS+ 서비스가 구동 중이지 않을 경우에 양호"	>> $filepath 2>&1
echo "■ 현황" >> $filepath 2>&1

SERVICE="ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.ypupdated"

if [ `ps -ef | egrep $SERVICE | grep -v "grep" | wc -l` -eq 0 ]; then
	echo "U-44,O,," >> $filepath 2>&1
	echo "NIS, NIS+ 서비스를 사용하지 않아 양호함"	>> $filepath 2>&1
else
	echo "U-44,X,," >> $filepath 2>&1
	echo "NIS, NIS+ 서비스를 사용해 취약함" >> $filepath 2>&1
fi

echo "[설정]" >> $filepath 2>&1
ps -ef | egrep $SERVICE | grep -v "grep"	>> $filepath 2>&1

NewLine $filepath


echo "U-45 Check Start..."
echo "■ U-45. 3. 서비스 관리 > 3.11 tftp, talk 서비스 비활성화" >> $filepath 2>&1
echo "■ 기준: tftp, talk, ntalk 서비스가 구동 중이지 않을 경우에 양호"	>> $filepath 2>&1
echo "■ 현황" >> $filepath 2>&1

if [ `cat /etc/services | awk -F" " '$1=="tftp" {print $1 "   " $2}' | grep "udp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]; then
	port=`cat /etc/services | awk -F" " '$1=="tftp" {print $1 "   " $2}' | grep "udp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`
	if [ `netstat -na | grep ":$port " | grep -i "^udp" | wc -l` -gt 0 ]; then
		NewLine 1.29.txt
	fi
fi

if [ `cat /etc/services | awk -F" " '$1=="talk" {print $1 "   " $2}' | grep "udp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]; then
	port=`cat /etc/services | awk -F" " '$1=="talk" {print $1 "   " $2}' | grep "udp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`
	if [ `netstat -na | grep ":$port " | grep -i "^udp" | wc -l` -gt 0 ]; then
		NewLine 1.29.txt
	fi
fi

if [ `cat /etc/services | awk -F" " '$1=="ntalk" {print $1 "   " $2}' | grep "udp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]; then
	port=`cat /etc/services | awk -F" " '$1=="ntalk" {print $1 "   " $2}' | grep "udp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`
	if [ `netstat -na | grep ":$port " | grep -i "^udp" | wc -l` -gt 0 ]; then
		NewLine 1.29.txt
	fi
fi

if [ -f 1.29.txt ]; then
	rm -f 1.29.txt
	echo "U-45,X,,"		>> $filepath 2>&1
	echo "tftp, talk, ntalk 서비스가 활성화 되어 있어 취약함"	>> $filepath 2>&1
else
	echo "U-45,O,,"		>> $filepath 2>&1
	echo "tftp, talk, ntalk 서비스가 비활성화 되어 있어 양호함"	>> $filepath 2>&1
fi
echo "[설정]" >> $filepath 2>&1
echo "① /etc/services 파일에서 포트 확인"	>> $filepath 2>&1
DividingLine $filepath

cat /etc/services | awk -F" " '$1=="tftp" {print $1 "   " $2}' | grep "udp"	>> $filepath 2>&1
cat /etc/services | awk -F" " '$1=="talk" {print $1 "   " $2}' | grep "udp"	>> $filepath 2>&1
cat /etc/services | awk -F" " '$1=="ntalk" {print $1 "  " $2}' | grep "udp"	>> $filepath 2>&1

NewLine $filepath
echo "② 서비스 포트 활성화 여부 확인"	>> $filepath 2>&1
DividingLine $filepath

if [ `cat /etc/services | awk -F" " '$1=="tftp" {print $1 "   " $2}' | grep "udp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]; then
	port=`cat /etc/services | awk -F" " '$1=="tftp" {print $1 "   " $2}' | grep "udp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`
	if [ `netstat -na | grep ":$port " | grep -i "^udp" | wc -l` -gt 0 ]; then
		netstat -na | grep ":$port " | grep -i "^udp"	>> $filepath 2>&1
	fi
fi

if [ `cat /etc/services | awk -F" " '$1=="talk" {print $1 "   " $2}' | grep "udp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]; then
	port=`cat /etc/services | awk -F" " '$1=="talk" {print $1 "   " $2}' | grep "udp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`
	if [ `netstat -na | grep ":$port " | grep -i "^udp" | wc -l` -gt 0 ]; then
		netstat -na | grep ":$port " | grep -i "^udp"	>> $filepath 2>&1
	fi
fi

if [ `cat /etc/services | awk -F" " '$1=="ntalk" {print $1 "   " $2}' | grep "udp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]; then
	port=`cat /etc/services | awk -F" " '$1=="ntalk" {print $1 "   " $2}' | grep "udp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`
	if [ `netstat -na | grep ":$port " | grep -i "^udp" | wc -l` -gt 0 ]; then
		netstat -na | grep ":$port " | grep -i "^udp"	>> $filepath 2>&1
	fi
fi

NewLine $filepath


echo "U-46 Check Start..."
echo "■ U-46. 3. 서비스 관리 > 3.12 Sendmail 버전 점검" >> $filepath 2>&1
echo "■ 기준: sendmail 버전이 8.13.8 이상이면 양호"	>> $filepath 2>&1
echo "■ 현황" >> $filepath 2>&1

echo "U-46,C,,"	>> $filepath 2>&1
echo "Sendmail 버전이 8.13.8 이상이 아닌 경우 취약함"	>> $filepath 2>&1
echo "Sendmail 버전이 8.13.8 이상인 경우 양호함"	>> $filepath 2>&1

echo "[설정]" >> $filepath 2>&1
echo "① /etc/services 파일에서 포트 확인"	>> $filepath 2>&1
DividingLine $filepath

cat /etc/services | awk -F" " '$1=="smtp" {print $1 "   " $2}' | grep "tcp"	>> $filepath 2>&1

NewLine $filepath
echo "② 서비스 포트 활성화 여부 확인"	>> $filepath 2>&1
DividingLine $filepath

if [ `cat /etc/services | awk -F" " '$1=="smtp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]; then
	port=`cat /etc/services | awk -F" " '$1=="smtp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`
	if [ `netstat -na | grep ":$port " | grep -i "^tcp" | wc -l` -gt 0 ]; then
		netstat -na | grep ":$port " | grep -i "^tcp"	>> $filepath 2>&1
		NewLine sendmail.txt
	fi
fi

if [ -f sendmail.txt ]; then
	rm -f sendmail.txt
else
	echo "Sendmail Service Disable"	>> $filepath 2>&1
fi

NewLine $filepath
echo "③ sendmail 버전확인"	>> $filepath 2>&1
DividingLine $filepath
if [ -f /etc/mail/sendmail.cf ]; then
	grep -v '^ *#' /etc/mail/sendmail.cf | grep DZ		>> $filepath 2>&1
	NewLine $filepath
else
	echo "/etc/mail/sendmail.cf 파일이 없음"	>> $filepath 2>&1
fi

NewLine $filepath


echo "U-47 Check Start..."
echo "■ U-47. 3. 서비스 관리 > 3.13 스팸 메일 릴레이 제한" >> $filepath 2>&1
echo "■ 기준: SMTP 서비스를 사용하지 않거나 릴레이 제한이 설정되어 있을 경우 양호"	>> $filepath 2>&1
echo "       : (R$*         $#error $@ 5.7.1 $: "550 Relaying denied" 해당 설정에 주석이 제거되어 있으면 양호)" >> $filepath 2>&1
echo "■ 현황" >> $filepath 2>&1

if [ `cat /etc/services | awk -F" " '$1=="smtp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]; then
	port=`cat /etc/services | awk -F" " '$1=="smtp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`
	if [ `netstat -na | grep ":$port " | grep -i "^tcp" | wc -l` -gt 0 ]; then
		NewLine sendmail.txt
	fi
fi

if [ -f sendmail.txt ]; then
	rm -f sendmail.txt

	#echo "③ /etc/mail/sendmail.cf 파일의 옵션 확인"	>> $filepath 2>&1
	#DividingLine $filepath

	echo "U-47,C,,"	>> $filepath 2>&1
	NewLine $filepath
	echo "[설정]" >> $filepath 2>&1
	if [ -f /etc/mail/sendmail.cf ]; then
		cat /etc/mail/sendmail.cf | grep "R$\*" | grep "Relaying denied"	>> $filepath 2>&1

		echo "SMTP 서비스를 사용하고 있는 경우 릴레이 제한이 설정되어 있는지 확인 필요 "	>> $filepath 2>&1
	else
		echo "/etc/mail/sendmail.cf 파일이 없음"	>> $filepath 2>&1
	fi
else
	echo "U-47,O,,"	>> $filepath 2>&1
	echo "SMTP 서비스를 사용하지 않아 양호함"	>> $filepath 2>&1
	echo "[설정]" >> $filepath 2>&1
fi

netstat -na | grep ":$port " | grep -i "^tcp"	>> $filepath 2>&1

NewLine $filepath


echo "U-48 Check Start..."
echo "■ U-48. 3. 서비스 관리 > 3.14 일반사용자의 Sendmail 실행 방지" >> $filepath 2>&1
echo "■ 기준: SMTP 서비스를 사용하지 않거나 릴레이 제한이 설정되어 있을 경우 양호"	>> $filepath 2>&1
echo "  (restrictqrun 옵션이 설정되어 있을 경우 양호)" >> $filepath 2>&1
echo "■ 현황" >> $filepath 2>&1

if [ `cat /etc/services | awk -F" " '$1=="smtp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]; then
	port=`cat /etc/services | awk -F" " '$1=="smtp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`
	if [ `netstat -na | grep ":$port " | grep -i "^tcp" | wc -l` -gt 0 ]; then
		NewLine sendmail.txt
	fi
fi

if [ -f sendmail.txt ]; then
	rm -f sendmail.txt

	if [ -f /etc/mail/sendmail.cf ]; then
		if [ `cat /etc/mail/sendmail.cf | grep -v '^ *#' | grep PrivacyOptions | grep "restrictqrun" | wc -l` -gt 0 ]; then
 			echo "U-48,O,,"	>> $filepath 2>&1
			echo "SMTP 서비스 활성화인 경우 일반 사용자의 Sendmail 실행 방지가 설정되어 양호함"	>> $filepath 2>&1
		else
			echo "U-48,X,,"	>> $filepath 2>&1
			echo "MTP 서비스 활성화인 경우 일반 사용자의 Sendmail 실행 방지가 설정되지 않아 취약함"	>> $filepath 2>&1
		fi
	else
		#임시로 C로 결과를 입력 검토 필요
		echo "U-48,C,,"	>> $filepath 2>&1
		echo "/etc/mail/sendmail.cf 파일이 없음"	>> $filepath 2>&1
	fi
else
	echo "U-48,O,,"	>> $filepath 2>&1
	echo "SMTP 서비스를 사용하지 않아 양호함"	>> $filepath 2>&1
fi
echo "[설정]" >> $filepath 2>&1
NewLine $filepath
echo "① /etc/mail/services 파일에서 포트 확인"	>> $filepath 2>&1
DividingLine $filepath

cat /etc/services | awk -F" " '$1=="smtp" {print $1 "   " $2}' | grep "tcp"	>> $filepath 2>&1

NewLine $filepath
echo "② 서비스 포트 활성화 여부 확인"	>> $filepath 2>&1
DividingLine $filepath
netstat -na | grep ":$port " | grep -i "^tcp"	>> $filepath 2>&1

if [ `cat /etc/services | awk -F" " '$1=="smtp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]; then
	port=`cat /etc/services | awk -F" " '$1=="smtp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`
	if [ `netstat -na | grep ":$port " | grep -i "^tcp" | wc -l` -gt 0 ]; then
		NewLine sendmail.txt
	fi
fi

if [ -f sendmail.txt ]; then
	rm -f sendmail.txt

	echo "③ /etc/mail/sendmail.cf 파일의 옵션 확인"	>> $filepath 2>&1
	DividingLine $filepath

	if [ -f /etc/mail/sendmail.cf ]; then
		grep -v '^ *#' /etc/mail/sendmail.cf | grep PrivacyOptions	>> $filepath 2>&1
	fi

fi

NewLine $filepath


echo "U-49 Check Start..."
echo "■ U-49. 3. 서비스 관리 > 3.15 DNS 보안 패치" >> $filepath 2>&1
echo "■ 기준: DNS 서비스를 사용하지 않거나, 양호한 버전을 사용하고 있을 경우에 양호"	>> $filepath 2>&1
echo "■ 현황" >> $filepath 2>&1

# DNS BIND 버전 지원 종료 확인
# https://www.isc.org/download/

# 2019년 7월 19일 기준 최신 버전
# 9.14.4 안정화 버전 EOL : 없음
# 9.11.9 안정화 버전 EOL : 2021년 12월
# 9.12.4-P2 취약한 버전 EOL : 2019년 5월

DNSPR=`ps -ef | grep named | grep -v "grep" | awk 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}'| grep "/" | uniq`
DNSPR=`echo $DNSPR | awk '{print $1}'`
if [ `ps -ef | grep named | grep -v grep | wc -l` -gt 0 ]; then
	if [ -f $DNSPR ]; then
		echo "U-49,C,,"	>> $filepath 2>&1
		echo "주기적으로 패치를 관리하고 있는 경우 양호함"	>> $filepath 2>&1
		echo "[설정]" >> $filepath 2>&1
		echo "BIND 버전 확인"	>> $filepath 2>&1
		DividingLine $filepath
		$DNSPR -v | grep BIND	>> $filepath 2>&1
	else
		echo "$DNSPR 파일이 없음"	>> $filepath 2>&1
	fi
else
	echo "U-49,O,,"	>> $filepath 2>&1
	echo "DNS 서비스를 사용하지 않아 양호함"	>> $filepath 2>&1
fi

NewLine $filepath


echo "U-50 Check Start..."
echo "■ U-50. 3. 서비스 관리 > 3.16 DNS Zone Transfer 설정"	>> $filepath 2>&1
echo "■ 기준: DNS 서비스를 사용하지 않거나 Zone Transfer 가 제한되어 있을 경우 양호"	>> $filepath 2>&1
echo "■ 현황" >> $filepath 2>&1

# ① DNS 프로세스 확인
DividingLine $filepath
if [ `ps -ef | grep named | grep -v "grep" | wc -l` -eq 0 ]; then
	echo "U-50,O,," >> $filepath 2>&1
	echo "DNS 서비스를 사용하지 않아 양호함"	>> $filepath 2>&1
else
	# /etc/named.conf 파일의 allow-transfer 확인

	DividingLine $filepath
	if [ -f /etc/named.conf ]; 	then
		if [ `cat /etc/named.conf | grep 'allow-transfer' | wc -l` -gt 0 ]; then
			echo "U-50,O,,"	>> $filepath 2>&1
			echo "DNS 서비스가 활성화인 경우 Zone Transfer를 허가된 사용자에게만 허용하였으므로 양호함"	>> $filepath 2>&1
			echo "[설정]" >> $filepath 2>&1
			cat /etc/named.conf | grep 'allow-transfer'	>> $filepath 2>&1
		else
			echo "U-50,X,,"	>> $filepath 2>&1
			echo "DNS 서비스가 활성화인 경우 Zone Transfer를 허가된 사용자에게만 허용하지 않아 취약함"	>> $filepath 2>&1
			echo "[설정]" >> $filepath 2>&1
		fi
	else
		echo "U-50,C,,"	>> $filepath 2>&1
		echo "/etc/named.conf 파일이 없음"	>> $filepath 2>&1
		echo "[설정]" >> $filepath 2>&1
	fi
fi

ps -ef | grep named | grep -v "grep"	>> $filepath 2>&1

NewLine $filepath

if [ `ls -al /etc/rc*.d/* | grep -i named | grep "/S" | wc -l` -gt 0 ]; then
	ls -al /etc/rc*.d/* | grep -i named | grep "/S"	>> $filepath 2>&1
	NewLine $filepath
fi

NewLine $filepath
echo "③ /etc/named.boot 파일의 xfrnets 확인"	>> $filepath 2>&1
DividingLine $filepath

if [ -f /etc/named.boot ]; then
	cat /etc/named.boot | grep "\xfrnets"	>> $filepath 2>&1
else
	echo "/etc/named.boot 파일이 없음"	>> $filepath 2>&1
fi

NewLine $filepath



echo "U-51 Check Start..."
echo "■ U-51. 3. 서비스 관리 > 3.24 ssh 원격접속 허용" >> $filepath 2>&1
echo "■ 기준: SSH 서비스가 활성화 되어 있으면 양호"	>> $filepath 2>&1
echo "■ 현황" >> $filepath 2>&1

NewFile ssh.txt
ServiceDIR="/etc/sshd_config /etc/ssh/sshd_config /usr/local/etc/sshd_config /usr/local/sshd/etc/sshd_config /usr/local/ssh/etc/sshd_config"
for file in $ServiceDIR; do
	if [ -f $file ]; then
		if [ `cat $file | grep ^Port | grep -v ^# | wc -l` -gt 0 ]; then
			cat $file | grep ^Port | grep -v ^# | awk '{print "SSH 설정파일('${file}'): " $0 }'		>> ssh.txt
			port1=`cat $file | grep ^Port | grep -v ^# | awk '{print $2}'`
			NewLine port1-search.txt
		else
			echo "SSH 설정파일($file): 포트 설정 X (Default 설정: 22포트 사용)"	>> ssh.txt
		fi
	fi
done

# 서비스 포트 점검
# ③ 서비스 포트 활성화 여부 확인
DividingLine $filepath

if [ -f port1-search.txt ]; then
	if [ `netstat -na | grep ":$port1 " | grep -i "^tcp" | grep -i "LISTEN" | wc -l` -eq 0 ]; then
		echo "U-51,X,,"	>> $filepath 2>&1
		echo "원격 접속 시 SSH 프로토콜을 사용하지 않아 취약함"	>> $filepath 2>&1
	else
		echo "U-51,O,,"	>> $filepath 2>&1
		echo "원격 접속 시 SSH 프로토콜을 사용해 양호함"	>> $filepath 2>&1
		NewLine $filepath
		echo "[설정]" >> $filepath 2>&1
		netstat -na | grep ":$port1 " | grep -i "^tcp" | grep -i "LISTEN"	>> $filepath 2>&1
	fi
else
	if [ `netstat -na | grep ":22 " | grep -i "^tcp" | grep -i "LISTEN" | wc -l` -eq 0 ]; then
		echo "U-51,X,,"	>> $filepath 2>&1
		echo "원격 접속 시 SSH 프로토콜을 사용하지 않아 취약함"	>> $filepath 2>&1
	else
		echo "U-51,O,,"	>> $filepath 2>&1
		echo "원격 접속 시 SSH 프로토콜을 사용해 양호함"	>> $filepath 2>&1
		NewLine $filepath
		echo "[설정]" >> $filepath 2>&1
		netstat -na | grep ":22 " | grep -i "^tcp" | grep -i "LISTEN"	>> $filepath 2>&1
	fi
fi

rm -f port1-search.txt
rm -f ssh.txt

NewLine $filepath


echo "U-52 Check Start..."
echo "■ U-52. 3. 서비스 관리 > 3.25 ftp 서비스 확인" >> $filepath 2>&1
echo "■ 기준: ftp 서비스가 비활성화 되어 있을 경우 양호"	>> $filepath 2>&1
echo "■ 현황" >> $filepath 2>&1

if [ `cat /etc/services | awk -F" " '$1=="ftp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]; then
	port=`cat /etc/services | awk -F" " '$1=="ftp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`
	if [ `netstat -nat | grep ":$port " | grep -i "^tcp" | grep -i "LISTEN" | wc -l` -gt 0 ]; then
		echo "U-52,X,," >> $filepath 2>&1
		echo "FTP 서비스가 활성화 되어 있어 취약함"	>> $filepath 2>&1
	else
		echo "U-52,O,," >> $filepath 2>&1
		echo "FTP 서비스가 비활성화 되어 있어 양호함"	>> $filepath 2>&1
	fi
else
	if [ `netstat -nat | grep ":21 " | grep -i "^tcp" | grep -i "LISTEN" | wc -l` -gt 0 ]; then
		echo "U-52,X,,"	>> $filepath 2>&1
		echo "FTP 서비스가 활성화 되어 있어 취약함"	>> $filepath 2>&1
	else
		echo "U-52,O,," >> $filepath 2>&1
		echo "FTP 서비스가 비활성화 되어 있어 양호함"	>> $filepath 2>&1
	fi
fi
echo "[설정]" >> $filepath 2>&1
echo "① /etc/services 파일에서 포트 확인"	>> $filepath 2>&1
DividingLine $filepath

if [ `cat /etc/services | awk -F" " '$1=="ftp" {print "(1)/etc/service파일:" $1 " " $2}' | grep "tcp" | wc -l` -gt 0 ]; then
	cat /etc/services | awk -F" " '$1=="ftp" {print "(1)/etc/service파일:" $1 " " $2}' | grep "tcp" >> $filepath 2>&1
else
	echo "(1)/etc/service파일: 포트 설정 X (Default 21번 포트)"	>> $filepath 2>&1
fi

NewLine $filepath
echo "② 서비스 포트 활성화 여부 확인"	>> $filepath 2>&1
DividingLine $filepath

################# /etc/services 파일에서 포트 확인 #################
if [ `cat /etc/services | awk -F" " '$1=="ftp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]; then
	port=`cat /etc/services | awk -F" " '$1=="ftp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`
	if [ `netstat -nat | grep ":$port " | grep -i "^tcp" | grep -i "LISTEN" | wc -l` -gt 0 ]; then
		netstat -nat | grep ":$port " | grep -i "^tcp" | grep -i "LISTEN"	>> $filepath 2>&1
		NewLine ftpenable.txt
	else
		NewLine ftpenable.txt
	fi
else
	if [ `netstat -nat | grep ":21 " | grep -i "^tcp" | grep -i "LISTEN" | wc -l` -gt 0 ]; then
		netstat -nat | grep ":21 " | grep -i "^tcp" | grep -i "LISTEN"	>> $filepath 2>&1
	else
		NewLine ftpenable.txt
	fi
fi

rm -f ftpenable.txt

NewLine $filepath


echo "U-53 Check Start..."
echo "■ U-53. 3. 서비스 관리 > 3.26 ftp 계정 shell 제한" >> $filepath 2>&1
echo "■ 기준: ftp 서비스가 비활성화 되어 있을 경우 양호" >> $filepath 2>&1
echo "  ftp 서비스 사용 시 ftp 계정의 Shell을 접속하지 못하도록 설정하였을 경우 양호"	>> $filepath 2>&1
echo "■ 현황" >> $filepath 2>&1

echo "U-53,C,,"	>> $filepath 2>&1
NewLine $filepath
echo "[설정]" >> $filepath 2>&1
echo "① /etc/services 파일에서 포트 확인"	>> $filepath 2>&1
DividingLine $filepath

if [ `cat /etc/services | awk -F" " '$1=="ftp" {print "(1)/etc/service파일:" $1 " " $2}' | grep "tcp" | wc -l` -gt 0 ]; then
	cat /etc/services | awk -F" " '$1=="ftp" {print "(1)/etc/service파일:" $1 " " $2}' | grep "tcp" >> $filepath 2>&1
else
	echo "(1)/etc/service파일: 포트 설정 X (Default 21번 포트)" >> $filepath 2>&1
fi

if [ -s vsftpd.txt ]; then
	if [ `cat $vsfile | grep "listen_port" | grep -v "^#" | awk '{print "(3)VsFTP 포트: " $1 "  " $2}' | wc -l` -gt 0 ]; then
		cat $vsfile | grep "listen_port" | grep -v "^#" | awk '{print "(3)VsFTP 포트: " $1 "  " $2}' >> $filepath 2>&1
	else
		echo "(2)VsFTP 포트: 포트 설정 X (Default 21번 포트 사용중)"	>> $filepath 2>&1
	fi
else
	echo "(2)VsFTP 포트: VsFTP가 설치되어 있지 않음"	>> $filepath 2>&1
fi

if [ -s proftpd.txt ]; then
	if [ `cat $profile | grep "Port" | grep -v "^#" | awk '{print "(2)ProFTP 포트: " $1 "  " $2}' | wc -l` -gt 0 ]; then
		cat $profile | grep "Port" | grep -v "^#" | awk '{print "(2)ProFTP 포트: " $1 "  " $2}'    >> $filepath 2>&1
	else
		echo "(3)ProFTP 포트: 포트 설정 X (/etc/service 파일에 설정된 포트를 사용중)"	>> $filepath 2>&1
	fi
else
	echo "(3)ProFTP 포트: ProFTP가 설치되어 있지 않음"	>> $filepath 2>&1
fi

NewLine $filepath
echo "② 서비스 포트 활성화 여부 확인"	>> $filepath 2>&1
DividingLine $filepath

################# /etc/services 파일에서 포트 확인 #################
if [ `cat /etc/services | awk -F" " '$1=="ftp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]; then
	port=`cat /etc/services | awk -F" " '$1=="ftp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`
	if [ `netstat -nat | grep ":$port " | grep -i "^tcp" | grep -i "LISTEN" | wc -l` -gt 0 ]; then
		netstat -nat | grep ":$port " | grep -i "^tcp" | grep -i "LISTEN"	>> $filepath 2>&1
		NewLine ftpenable.txt
	fi
else
	netstat -nat | grep ":21 " | grep -i "^tcp" | grep -i "LISTEN"	>> $filepath 2>&1
	NewLine ftpenable.txt
fi

################# vsftpd 에서 포트 확인 ############################
if [ -s vsftpd.txt ]; then
	if [ `cat $vsfile | grep "listen_port" | grep -v "^#" | awk -F"=" '{print $2}' | wc -l` -eq 0 ]; then
		port=21
	else
		port=`cat $vsfile | grep "listen_port" | grep -v "^#" | awk -F"=" '{print $2}'`
	fi

	if [ `netstat -nat | grep ":$port " | grep -i "^tcp" | grep -i "LISTEN" | wc -l` -gt 0 ]; then
		netstat -nat | grep ":$port " | grep -i "^tcp" | grep -i "LISTEN"	>> $filepath 2>&1
		NewLine ftpenable.txt
	fi
fi

################# proftpd 에서 포트 확인 ###########################
if [ -s proftpd.txt ]; then
	port=`cat $profile | grep "Port" | grep -v "^#" | awk '{print $2}'`
	if [ `netstat -nat | grep ":$port " | grep -i "^tcp" | grep -i "LISTEN" | wc -l` -gt 0 ]; then
		netstat -nat | grep ":$port " | grep -i "^tcp" | grep -i "LISTEN"	>> $filepath 2>&1
		NewLine ftpenable.txt
	fi
fi

NewLine $filepath


echo "U-54 Check Start..."
echo "■ U-54. 3. 서비스 관리 > 3.27 ftpusers 파일 소유자 및 권한 설정" >> $filepath 2>&1
echo "■ 기준: ftpusers 파일의 소유자가 root이고, 권한이 640 미만이면 양호" >> $filepath 2>&1
echo "  [FTP 종류별 적용되는 파일]" >> $filepath 2>&1
echo "  (1)ftpd: /etc/ftpusers 또는 /etc/ftpd/ftpusers"	>> $filepath 2>&1
echo "  (2)proftpd: /etc/ftpusers 또는 /etc/ftpd/ftpusers"	>> $filepath 2>&1
echo "  (3)vsftpd: /etc/vsftpd/ftpusers, /etc/vsftpd/user_list (또는 /etc/vsftpd.ftpusers, /etc/vsftpd.user_list)" >> $filepath 2>&1
echo "■ 현황" >> $filepath 2>&1

echo "U-54,C,," >> $filepath 2>&1
echo "[설정]" >> $filepath 2>&1
echo "ftpusers 파일의 소유자와 권한 확인 필요 " >> $filepath 2>&1
NewLine $filepath
echo "① /etc/services 파일에서 포트 확인"	>> $filepath 2>&1
DividingLine $filepath

if [ `cat /etc/services | awk -F" " '$1=="ftp" {print "(1)/etc/service파일:" $1 " " $2}' | grep "tcp" | wc -l` -gt 0 ]; then
	cat /etc/services | awk -F" " '$1=="ftp" {print "(1)/etc/service파일:" $1 " " $2}' | grep "tcp" >> $filepath 2>&1
else
	echo "(1)/etc/service파일: 포트 설정 X (Default 21번 포트)" >> $filepath 2>&1
fi

if [ -s vsftpd.txt ]; then
	if [ `cat $vsfile | grep "listen_port" | grep -v "^#" | awk '{print "(3)VsFTP 포트: " $1 "  " $2}' | wc -l` -gt 0 ]; then
		cat $vsfile | grep "listen_port" | grep -v "^#" | awk '{print "(3)VsFTP 포트: " $1 "  " $2}' >> $filepath 2>&1
	else
		echo "(2)VsFTP 포트: 포트 설정 X (Default 21번 포트 사용중)"	>> $filepath 2>&1
	fi
else
	echo "(2)VsFTP 포트: VsFTP가 설치되어 있지 않음"	>> $filepath 2>&1
fi

if [ -s proftpd.txt ]; then
	if [ `cat $profile | grep "Port" | grep -v "^#" | awk '{print "(2)ProFTP 포트: " $1 "  " $2}' | wc -l` -gt 0 ]; then
		cat $profile | grep "Port" | grep -v "^#" | awk '{print "(2)ProFTP 포트: " $1 "  " $2}'	>> $filepath 2>&1
	else
		echo "(3)ProFTP 포트: 포트 설정 X (/etc/service 파일에 설정된 포트를 사용중)"	>> $filepath 2>&1
	fi
else
	echo "(3)ProFTP 포트: ProFTP가 설치되어 있지 않음"	>> $filepath 2>&1
fi

NewLine $filepath
echo "② 서비스 포트 활성화 여부 확인"	>> $filepath 2>&1
DividingLine $filepath

################# /etc/services 파일에서 포트 확인 #################
if [ `cat /etc/services | awk -F" " '$1=="ftp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]; then
	port=`cat /etc/services | awk -F" " '$1=="ftp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`
	if [ `netstat -nat | grep ":$port " | grep -i "^tcp" | grep -i "LISTEN" | wc -l` -gt 0 ]; then
		netstat -nat | grep ":$port " | grep -i "^tcp" | grep -i "LISTEN"	>> $filepath 2>&1
		NewLine ftpenable.txt
	fi
else
	netstat -nat | grep ":21 " | grep -i "^tcp" | grep -i "LISTEN"	>> $filepath 2>&1
	NewLine ftpenable.txt
fi

################# vsftpd 에서 포트 확인 ############################
if [ -s vsftpd.txt ]; then
	if [ `cat $vsfile | grep "listen_port" | grep -v "^#" | awk -F"=" '{print $2}' | wc -l` -eq 0 ]; then
		port=21
	else
		port=`cat $vsfile | grep "listen_port" | grep -v "^#" | awk -F"=" '{print $2}'`
	fi

	if [ `netstat -nat | grep ":$port " | grep -i "^tcp" | grep -i "LISTEN" | wc -l` -gt 0 ]; then
		netstat -nat | grep ":$port " | grep -i "^tcp" | grep -i "LISTEN"	>> $filepath 2>&1
		NewLine ftpenable.txt
	fi
fi

################# proftpd 에서 포트 확인 ###########################
if [ -s proftpd.txt ]; then
	port=`cat $profile | grep "Port" | grep -v "^#" | awk '{print $2}'`

	if [ `netstat -nat | grep ":$port " | grep -i "^tcp" | grep -i "LISTEN" | wc -l` -gt 0 ]; then
		netstat -nat | grep ":$port " | grep -i "^tcp" | grep -i "LISTEN"	>> $filepath 2>&1
		NewLine ftpenable.txt
	fi
fi

if [ -f ftpenable.txt ]; then
	rm -f ftpenable.txt
else
	echo "FTP Service Disable"	>> $filepath 2>&1
fi

NewLine $filepath
echo "③ ftpusers 파일 소유자 및 권한 확인" >> $filepath 2>&1
DividingLine $filepath

NewFile ftpusers.txt

ServiceDIR="/etc/ftpusers /etc/ftpd/ftpusers /etc/vsftpd/ftpusers /etc/vsftpd.ftpusers /etc/vsftpd/user_list /etc/vsftpd.user_list"

for file in $ServiceDIR; do
	if [ -f $file ]; then
		ls -alL $file	>> ftpusers.txt
	fi
done

if [ `cat ftpusers.txt | wc -l` -gt 1 ]; then
	cat ftpusers.txt | grep -v "^ *$"	>> $filepath 2>&1
	NewLine $filepath
else
	NewLine $filepath
fi

rm -f ftpusers.txt

NewLine $filepath


echo "U-55 Check Start..."
echo "■ U-55. 3. 서비스 관리 > 3.28 ftpusers 파일 설정" >> $filepath 2>&1
echo "■ 기준: ftp 를 사용하지 않거나, ftp 사용시 ftpusers 파일에 root가 있을 경우 양호" >> $filepath 2>&1
echo "  [FTP 종류별 적용되는 파일]" >> $filepath 2>&1
echo "  (1)ftpd: /etc/ftpusers 또는 /etc/ftpd/ftpusers" >> $filepath 2>&1
echo "  (2)proftpd: /etc/ftpusers 또는 /etc/ftpd/ftpusers" >> $filepath 2>&1
echo "  (3)vsftpd: /etc/vsftpd/ftpusers, /etc/vsftpd/user_list (또는 /etc/vsftpd.ftpusers, /etc/vsftpd.user_list)" >> $filepath 2>&1
echo "■ 현황" >> $filepath 2>&1

U64log=U64log.txt
echo "① /etc/services 파일에서 포트 확인"	>> $U64log 2>&1
DividingLine $U64log

if [ `cat /etc/services | awk -F" " '$1=="ftp" {print "(1)/etc/service파일:" $1 " " $2}' | grep "tcp" | wc -l` -gt 0 ]; then
	cat /etc/services | awk -F" " '$1=="ftp" {print "(1)/etc/service파일:" $1 " " $2}' | grep "tcp" >> $U64log 2>&1
else
	echo "(1)/etc/service파일: 포트 설정 X (Default 21번 포트)"	>> $U64log 2>&1
fi

if [ -s vsftpd.txt ]; then
	if [ `cat $vsfile | grep "listen_port" | grep -v "^#" | awk '{print "(3)VsFTP 포트: " $1 "  " $2}' | wc -l` -gt 0 ]; then
		cat $vsfile | grep "listen_port" | grep -v "^#" | awk '{print "(3)VsFTP 포트: " $1 "  " $2}' >> $U64log 2>&1
	else
		echo "(2)VsFTP 포트: 포트 설정 X (Default 21번 포트 사용중)"	>> $U64log 2>&1
	fi
else
	echo "(2)VsFTP 포트: VsFTP가 설치되어 있지 않음"	>> $U64log 2>&1
fi

if [ -s proftpd.txt ]; then
	if [ `cat $profile | grep "Port" | grep -v "^#" | awk '{print "(2)ProFTP 포트: " $1 "  " $2}' | wc -l` -gt 0 ]; then
		cat $profile | grep "Port" | grep -v "^#" | awk '{print "(2)ProFTP 포트: " $1 "  " $2}'	>> $U64log 2>&1
	else
		echo "(3)ProFTP 포트: 포트 설정 X (/etc/service 파일에 설정된 포트를 사용중)"	>> $U64log 2>&1
	fi
else
	echo "(3)ProFTP 포트: ProFTP가 설치되어 있지 않음"	>> $U64log 2>&1
fi

#NewLine $filepath
echo "② 서비스 포트 활성화 여부 확인"	>> $U64log 2>&1
DividingLine $U64log

################# /etc/services 파일에서 포트 확인 #################
if [ `cat /etc/services | awk -F" " '$1=="ftp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]; then
	port=`cat /etc/services | awk -F" " '$1=="ftp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`
	if [ `netstat -nat | grep ":$port " | grep -i "^tcp" | grep -i "LISTEN" | wc -l` -gt 0 ]; then
		netstat -nat | grep ":$port " | grep -i "^tcp" | grep -i "LISTEN"	>> $U64log 2>&1
		NewLine ftpenable.txt
	fi
else
	netstat -nat | grep ":21 " | grep -i "^tcp" | grep -i "LISTEN"	>> $U64log 2>&1
	NewLine ftpenable.txt
fi

################# vsftpd 에서 포트 확인 ############################
if [ -s vsftpd.txt ]; then
	if [ `cat $vsfile | grep "listen_port" | grep -v "^#" | awk -F"=" '{print $2}' | wc -l` -eq 0 ]; then
		port=21
	else
		port=`cat $vsfile | grep "listen_port" | grep -v "^#" | awk -F"=" '{print $2}'`
	fi

	if [ `netstat -nat | grep ":$port " | grep -i "^tcp" | grep -i "LISTEN" | wc -l` -gt 0 ]; then
		netstat -nat | grep ":$port " | grep -i "^tcp" | grep -i "LISTEN"	>> $U64log 2>&1
		NewLine ftpenable.txt
	fi
fi

################# proftpd 에서 포트 확인 ###########################
if [ -s proftpd.txt ]; then
	port=`cat $profile | grep "Port" | grep -v "^#" | awk '{print $2}'`
	if [ `netstat -nat | grep ":$port " | grep -i "^tcp" | grep -i "LISTEN" | wc -l` -gt 0 ]; then
		netstat -nat | grep ":$port " | grep -i "^tcp" | grep -i "LISTEN"	>> $U64log 2>&1
		NewLine ftpenable.txt
	fi
fi

if [ -f ftpenable.txt ]; then
	echo "③ ftpusers 파일 설정 확인"	>> $U64log 2>&1
	DividingLine $U64log
	NewLine ftpusers.txt

	ServiceDIR="/etc/ftpusers /etc/ftpd/ftpusers /etc/vsftpd/ftpusers /etc/vsftpd.ftpusers /etc/vsftpd/user_list /etc/vsftpd.user_list"

	for file in $ServiceDIR; do
		if [ -f $file ]; then
			if [ `cat $file | grep "root" | grep -v "^#" | wc -l` -gt 0 ]; then
				echo "● $file 파일내용: `cat $file | grep "root" | grep -v "^#"` 계정이 등록되어 있음."  >> ftpusers.txt
				echo "U-55,O,,"	>> $filepath 2>&1
				echo "FTP 서비스가 활성화 되어 있는 경우 root 계정 접속을 차단함"	>> $filepath 2>&1
				echo "[설정]" >> $filepath 2>&1
			else
				echo "● $file 파일내용: root 계정이 등록되어 있지 않음."	>> ftpusers.txt
				echo "U-55,X,,"	>> $filepath 2>&1
				echo "FTP 서비스가 활성화 되어 있는 경우 root 계정 접속을 허용함"	>> $filepath 2>&1
				echo "[설정]" >> $filepath 2>&1
			fi
		fi
	done
else
	echo "U-55,O,,"	>> $filepath 2>&1
	echo "FTP 서비스가 비활성화 되어 있어 양호함"	>> $filepath 2>&1
fi

#진단에 필요한 정보를 추가
NewLine $filepath
cat $U64log >> $filepath 2>&1

if [ -f check.txt ]; then
	cat ftpusers.txt | grep -v "^ *$"	>> $filepath 2>&1
else
	echo "ftpusers 파일을 찾을 수 없음 (FTP 서비스 동작 시 취약)"	>> $filepath 2>&1
fi

#파일 정리
rm -f ftpenable.txt
rm -f ftpusers.txt
rm -f check.txt
rm -f $U64log

NewLine $filepath



echo "U-56 Check Start..."
echo "■ U-56.3. 서비스 관리 > 3.29 at 서비스 권한 설정" >> $filepath 2>&1
echo "■ 기준: at.allow 또는 at.deny 파일 권한이 640 이하이면 양호"	>> $filepath 2>&1
echo "■ 현황" >> $filepath 2>&1

# 1 : 파일이 없음
# 2 : 파일 권한 양호
# 3 : 파일 권한 취약
U65_ALLOW=0
U65_DENY=0

if [ -f /etc/at.allow ]; then
	if [ `stat -c %a /etc/at.allow` -le 640 ]; then
		U65_ALLOW=2
	else
		U65_ALLOW=3
	fi
else
	U65_ALLOW=1
fi

if [ -f /etc/at.deny ]; then
	if [ `stat -c %a /etc/at.deny` -le 640 ]; then
		U65_DENY=2
	else
		U65_DENY=3
	fi
else
	U65_DENY=1
fi

if [ $U65_ALLOW -eq 1 -a $U65_DENY -eq 1 ]; then
	echo "U-56,O,," >> $filepath 2>&1
	echo "at.allow와 at.deny 파일이 없어 양호함"	>> $filepath 2>&1
elif [ $U65_ALLOW -eq 3 -o $U65_DENY -eq 3 ]; then
	echo "U-56,X,," >> $filepath 2>&1
	echo "at.allow 또는 at.deny 파일이 권한이 640보다 높아 취약함"	>> $filepath 2>&1
else
	echo "U-56,O,," >> $filepath 2>&1
	echo "at.allow와 at.deny 파일의 권한이 640보다 낮거나 같아 양호함"	>> $filepath 2>&1
fi

if [ $U65_ALLOW -ne 1 ]; then
	echo "[설정]" >> $filepath 2>&1
	ls -l /etc/at.allow	>> $filepath 2>&1
fi

if [ $U65_DENY -ne 1 ]; then
	echo "[설정]" >> $filepath 2>&1
	ls -l /etc/at.deny	>> $filepath 2>&1
fi

NewLine $filepath



echo "U-57 Check Start..."
echo "■ U-57. 3. 서비스 관리 > 3.30 SNMP 서비스 구동 점검" >> $filepath 2>&1
echo "■ 기준: SNMP 서비스를 불필요한 용도로 사용하지 않을 경우 양호"	>> $filepath 2>&1
echo "■ 현황" >> $filepath 2>&1

# SNMP서비스는 동작시 /etc/service 파일의 포트를 사용하지 않음.
if [ `netstat -na | grep ":161 " | grep -i "^udp" | wc -l` -eq 0 ]; then
	echo "U-57,O,,"	>> $filepath 2>&1
	echo "SNMP 서비스를 사용하지 않아 양호함"	>> $filepath 2>&1
	DividingLine $filepath
	echo "[설정]" >> $filepath 2>&1
	netstat -na | grep ":161 " | grep -i "^udp"	>> $filepath 2>&1
else
	echo "U-57,X,,"	>> $filepath 2>&1
	echo "SNMP 서비스를 사용해 취약함"	>> $filepath 2>&1
	echo "SNMP 서비스 활성화 여부 확인(UDP 161)"	>> $filepath 2>&1
	DividingLine $filepath
	echo "[설정]" >> $filepath 2>&1
	netstat -na | grep ":161 " | grep -i "^udp"	>> $filepath 2>&1
fi

NewLine $filepath



echo "U-58 Check Start..."
echo "■ U-58. 3. 서비스 관리 > 3.31 SNMP 서비스 Community String의 복잡성 설정" >> $filepath 2>&1
echo "■ 기준: SNMP Community 이름이 public, private 이 아닐 경우 양호"	>> $filepath 2>&1
echo "■ 현황" >> $filepath 2>&1

if [ `netstat -na | grep ":161 " | grep -i "^udp" | wc -l` -eq 0 ]; then
	echo "U-58,O,,"	>> $filepath 2>&1
	echo "SNMP 서비스를 사용하지 않아 양호함"	>> $filepath 2>&1
else
	echo "U-58,C,,"	>> $filepath 2>&1
	echo "[설정]" >> $filepath 2>&1
	netstat -na | grep ":161 " | grep -i "^udp"	>> $filepath 2>&1

	echo "② SNMP Community String 설정 값"	>> $filepath 2>&1
	DividingLine $filepath

	if [ -f /etc/snmpd.conf ]; then
		echo "● /etc/snmpd.conf 파일 설정:"	>> $filepath 2>&1
		DividingLine $filepath

		cat /etc/snmpd.conf | grep -E -i "public|private|com2sec|community" | grep -v "^#" >> $filepath 2>&1

		NewLine $filepath

		NewLine snmpd.txt
	fi

	if [ -f /etc/snmp/snmpd.conf ]; then
		echo "● /etc/snmp/snmpd.conf 파일 설정:"	>> $filepath 2>&1
		DividingLine $filepath

		cat /etc/snmp/snmpd.conf | grep -E -i "public|private|com2sec|community" | grep -v "^#" >> $filepath 2>&1

		NewLine $filepath

		NewLine snmpd.txt
	fi

	if [ -f /etc/snmp/conf/snmpd.conf ]; then
		echo "● /etc/snmp/conf/snmpd.conf 파일 설정:"	>> $filepath 2>&1
		DividingLine $filepath

		cat /etc/snmp/conf/snmpd.conf | grep -E -i "public|private|com2sec|community" | grep -v "^#" >> $filepath 2>&1

		NewLine $filepath

		NewLine snmpd.txt
	fi

	if [ -f /SI/CM/config/snmp/snmpd.conf ]; then
		echo "● /SI/CM/config/snmp/snmpd.conf 파일 설정:"	>> $filepath 2>&1
		DividingLine $filepath

		cat /SI/CM/config/snmp/snmpd.conf | grep -E -i "public|private|com2sec|community" | grep -v "^#" >> $filepath 2>&1

		NewLine $filepath

		NewLine snmpd.txt
	fi

	if [ -f snmpd.txt ]; then
		rm -f snmpd.txt
	else
		NewLine $filepath
	fi
fi

NewLine $filepath



echo "U-59 Check Start..."
echo "■ U-59. 3. 서비스 관리 > 3.32 로그온 시 경고 메시지 제공" >> $filepath 2>&1
echo "■ 기준: /etc/issue.net과 /etc/motd 파일에 로그온 경고 메시지가 설정되어 있을 경우 양호"	>> $filepath 2>&1
echo "■ 현황" >> $filepath 2>&1

echo "U-59,C,,"	>> $filepath 2>&1
echo "[설정]" >> $filepath 2>&1
echo "● /etc/services 파일에서 포트 확인"	>> $filepath 2>&1
DividingLine $filepath

cat /etc/services | awk -F" " '$1=="telnet" {print $1 "   " $2}' | grep "tcp"	>> $filepath 2>&1

NewLine $filepath
echo "● 서비스 포트 활성화 여부 확인"	>> $filepath 2>&1
DividingLine $filepath

if [ `cat /etc/services | awk -F" " '$1=="telnet" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]; then
	port=`cat /etc/services | awk -F" " '$1=="telnet" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	if [ `netstat -na | grep ":$port " | grep -i "^tcp" | wc -l` -gt 0 ]; then
		netstat -na | grep ":$port " | grep -i "^tcp" | grep -i "LISTEN"	>> $filepath 2>&1
	else
		echo "Telnet Service Disable"	>> $filepath 2>&1
	fi
fi

NewLine $filepath
echo "① /etc/motd 파일 설정: "	>> $filepath 2>&1
DividingLine $filepath
if [ -f /etc/motd ]; then
	if [ `cat /etc/motd | grep -v "^ *$" | wc -l` -gt 0 ]; then
		cat /etc/motd | grep -v "^ *$"	>> $filepath 2>&1
	else
		NewLine $filepath
	fi
else
	echo "/etc/motd 파일이 없음"	>> $filepath 2>&1
fi

NewLine $filepath
echo "② /etc/issue.net 파일 설정:"	>> $filepath 2>&1
DividingLine $filepath

if [ -f /etc/issue.net ]; then
	if [ `cat /etc/issue.net | grep -v "^#" | grep -v "^ *$" | wc -l` -gt 0 ]; then
		cat /etc/issue.net | grep -v "^#" | grep -v "^ *$"	>> $filepath 2>&1
	else
		NewLine $filepath
	fi
else
	echo "/etc/issue.net 파일이 없음"	>> $filepath 2>&1
fi

NewLine $filepath



echo "U-60 Check Start..."
echo "■ U-60. 3. 서비스 관리 > 3.33 NFS 설정파일 접근권한" >> $filepath 2>&1
echo "■ 기준: NFS 서버 데몬이 동작하지 않거나, /etc/exports 파일의 권한이 644 이하이면 양호"	>> $filepath 2>&1
echo "(/etc/exports 파일 없으면 NFS서비스 이용이 불가능함으로 양호)" >> $filepath 2>&1
echo "■ 현황" >> $filepath 2>&1

if [ `ps -ef | grep "nfsd" | egrep -v "statdaemon|automountd|emi" | grep -v "grep" | wc -l` -gt 0 ]; then
	if [ -f /etc/exports ]; then
		if [ `stat -c %a /etc/exports` -le 644 ]; then
			echo "U-60,O,,"	>> $filepath 2>&1
			echo "/etc/exports 파일의 권한이 644보다 낮거나 같아 양호함" >> $filepath 2>&1
		else
			echo "U-60,X,,"	>> $filepath 2>&1
			echo "/etc/exports 파일의 권한이 644보다 높아 취약함" >> $filepath 2>&1
		fi
		echo "[설정]" >> $filepath 2>&1
		ls -alL /etc/exports	>> $filepath 2>&1
	else
		echo "U-60,O,,"	>> $filepath 2>&1
		echo "/etc/exports 파일이 없어 양호함"	>> $filepath 2>&1
		echo "[설정]" >> $filepath 2>&1
	fi

	echo "NFS Server Daemon(nfsd)확인"	>> $filepath 2>&1
	DividingLine $filepath

	ps -ef | grep "nfsd" | egrep -v "statdaemon|automountd|emi" | grep -v "grep"	>> $filepath 2>&1
else
	echo "U-60,O,,"	>> $filepath 2>&1
	echo "NFS 서버 데몬이 비활성화되어 있어 양호함"	>> $filepath 2>&1
fi

NewLine $filepath



echo "U-61 Check Start..."
echo "■ U-61.3. 서비스 관리 > 3.34 expn, vrfy 명령어 제한" >> $filepath 2>&1
echo "■ 기준: SMTP 서비스를 사용하지 않거나 noexpn, novrfy 옵션이 설정되어 있을 경우 양호"	>> $filepath 2>&1
echo "■ 현황" >> $filepath 2>&1

#서비스 포트 활성화 여부 확인

#services 목록 중 smtp이면서 tcp인 포트가 있는지 확인
#ex) smtp  25/tcp
if [ `cat /etc/services | awk -F " " '$1=="smtp" {print $1 "   " $2}' | grep "tcp" | awk -F " " '{print $2}' | awk -F "/" '{print $1}' | wc -l` -gt 0 ]; then
	port=`cat /etc/services | awk -F " " '$1=="smtp" {print $1 "   " $2}' | grep "tcp" | awk -F " " '{print $2}' | awk -F "/" '{print $1}'`

	#netstat 목록에서 tcp로 시작하며 :port번호가 일치하는 수를 확인
	if [ `netstat -na | grep ":$port " | grep -i "^tcp" | wc -l` -gt 0 ]; then
		#netstat -na | grep ":$port " | grep -i "^tcp"
		NewLine sendmail.txt
	fi
fi

if [ -f sendmail.txt ]; then
	rm -f sendmail.txt
#	NewLine $filepath
#	echo "③ /etc/mail/sendmail.cf 파일의 옵션 확인"	>> $filepath 2>&1
#	DividingLine $filepath

	if [ -f /etc/mail/sendmail.cf ]; then
		echo "U-61,O,,"	>> $filepath 2>&1

		grep -v '^ *#' /etc/mail/sendmail.cf | grep PrivacyOptions	>> $filepath 2>&1
		echo "MTP 서비스 활성화일 경우 noexpn, novrfy 옵션이 설정되어 있음"	>> $filepath 2>&1
	else
		echo "U-61,X,,"	>> $filepath 2>&1
		echo "MTP 서비스 활성화일 경우 noexpn, novrfy 옵션이 설정되어 있지 않아 취약함"	>> $filepath 2>&1
	fi
else
	echo "U-61,O,,"	>> $filepath 2>&1
	echo "SMTP 서비스 비활성화되어 있어 양호함"	>> $filepath 2>&1
fi
echo "[설정]" >> $filepath 2>&1
echo "① /etc/services 파일에서 포트 확인"	>> $filepath 2>&1
DividingLine $filepath

cat /etc/services | awk -F" " '$1=="smtp" {print $1 "   " $2}' | grep "tcp"	>> $filepath 2>&1

NewLine $filepath
echo "② 서비스 포트 활성화 여부 확인"	>> $filepath 2>&1
DividingLine $filepath

if [ `cat /etc/services | awk -F" " '$1=="smtp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]; then
	port=`cat /etc/services | awk -F" " '$1=="smtp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`
	if [ `netstat -na | grep ":$port " | grep -i "^tcp" | wc -l` -gt 0 ]; then
		netstat -na | grep ":$port " | grep -i "^tcp"	>> $filepath 2>&1
	fi
fi

NewLine $filepath



echo "U-62 Check Start..."
echo "■ U-62. 4. 로그 관리 > 4.1 최신 보안패치 및 벤더 권고사항 적용" 			>> $filepath 2>&1
echo "■ 기준: 패치 적용 정책을 수립하여 주기적으로 패치를 관리하고 있을 경우 양호"	>> $filepath 2>&1
echo "■ 현황" >> $filepath 2>&1

echo "U-62,C,,"		>> $filepath 2>&1
echo "[수동진단] 패치 적용 정책 관리 및 수행하는지 인터뷰" >> $filepath 2>&1
NewLine $filepath
echo "[설정]" >> $filepath 2>&1
echo "OS Version" >> $filepath 2>&1
cat /etc/*-release | uniq | head -1 >> $filepath 2>&1
NewLine $filepath



echo "U-63 Check Start..."
echo "■ U-63. 5. 보안 관리 > 5.1 로그의 정기적 검토 및 보고" >> $filepath 2>&1
echo "■ 기준: 로그기록에 대해 정기적 검토, 분석, 리포트 작성 및 보고가 이루어지고 있는 경우 양호"	>> $filepath 2>&1
echo "■ 현황" >> $filepath 2>&1

echo "U-63,C,,"	>> $filepath 2>&1
NewLine $filepath
echo "[수동진단] 담당자 인터뷰 및 증적확인"	>> $filepath 2>&1
DividingLine $filepath
echo "① 일정 주기로 로그를 점검하고 있는가?"	>> $filepath 2>&1
echo "② 로그 점검결과에 따른 결과보고서가 존재하는가?"	>> $filepath 2>&1

NewLine $filepath



echo "U-64 Check Start..."
echo "■ U-64. 5. 보안 관리 > 5.2 정책에 따른 시스템 로깅 설정" >> $filepath 2>&1
echo "■ 기준: rsyslog 에 중요 로그 정보에 대한 설정이 되어 있을 경우 양호"	>> $filepath 2>&1
echo "■ 현황" >> $filepath 2>&1

echo "U-64,C,,"	>> $filepath 2>&1
echo "[수동진단]"	>> $filepath 2>&1
echo "① SYSLOG 데몬 동작 확인"	>> $filepath 2>&1
DividingLine $filepath

if [ `ps -ef | grep 'rsyslog' | grep -v 'grep' | wc -l` -eq 0 ]; then
	echo "RSYSLOG Service Disable"	>> $filepath 2>&1
else
	ps -ef | grep 'rsyslog' | grep -v 'grep'	>> $filepath 2>&1
fi

NewLine $filepath
echo "② SYSLOG 설정 확인"	>> $filepath 2>&1
DividingLine $filepath

if [ -f /etc/rsyslog.conf ]; then
	if [ `cat /etc/rsyslog.conf | grep -v "^#" | grep -v "^ *$" | wc -l` -gt 0 ]; then
		cat /etc/rsyslog.conf | grep -v "^#" | grep -v "^ *$"	>> $filepath 2>&1
	else
		echo "/etc/rsyslog.conf 파일에 설정 내용이 없음(주석, 빈칸 제외)"	>> $filepath 2>&1
	fi
else
	echo "/etc/rsyslog.conf 파일이 없음"	>> $filepath 2>&1
fi

rm -f proftpd.txt
rm -f vsftpd.txt

NewLine $filepath


echo "------------------------Basic RAW---------------------------" >> $filepath 2>&1

#HOSTNAME
echo "HOSTNAME : $HOSTNAME" >> $filepath 2>&1

#OS
# CentOS 7 기준으로 /etc/centos-release로 확인 가능
oscheck=$(cat /etc/*-release | uniq | head -1)
echo "OS : $oscheck" >> $filepath 2>&1

#IP
# print $2를 쓰는데 OS에 따라서 $3이 될 수 있으니 보완 필요
CheckVersion
if [ $? -ge 7 ]; then
	ipcheck=$(hostname -i | awk '{print $2}')
	echo "IP : $ipcheck" >> $filepath 2>&1
else
	ipcheck=$(hostname -i | awk '{print $1}')
	echo "IP : $ipcheck" >> $filepath 2>&1
fi

#자산 중요도
echo "자산중요도 : 기밀" >> $filepath 2>&1
NewLine $filepath

echo "------------------------시스템 정보------------------------" >> $filepath 2>&1
NewLine $filepath

echo "--OS Information--"	>> $filepath 2>&1
uname -a	>> $filepath 2>&1
NewLine $filepath

echo "--IP Information--" >> $filepath 2>&1
ifconfig -a	>> $filepath 2>&1
NewLine $filepath

echo "--Network Status(1)--" >> $filepath 2>&1
netstat -an | egrep -i "LISTEN|ESTABLISHED"	>> $filepath 2>&1
NewLine $filepath

echo "--Network Status(2)--" >> $filepath 2>&1
netstat -nap | egrep -i "tcp|udp"	>> $filepath 2>&1
NewLine $filepath

echo "--Routing Information--" >> $filepath 2>&1
netstat -rn	>> $filepath 2>&1
NewLine $filepath

echo "--Process Status--" >> $filepath 2>&1
ps -ef	>> $filepath 2>&1
NewLine $filepath

echo "--User Env--" >> $filepath 2>&1
env	>> $filepath 2>&1
NewLine $filepath

echo ''
echo ''
echo "Please Return your $filepath"
echo ''

#UTF-8을 ANSI(euc-kr)로 변경(다인슈에서 Linux는 UTF-8로 지정)
#iconv -f UTF-8 -t euc-kr $HOSTNAME-linux.txt > $filepath

#스크립트 종료
exit
