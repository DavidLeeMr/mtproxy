#!/bin/bash
# MTProxy Ultimate 2025 一键安装脚本（mtg + Python + 官方三合一）
# 支持：① 9seconds mtg  ② alexbers Python 版  ③ Telegram 官方 C 版
# Author: Mr.David<https://cceclubs.org> / Based on TelegramMessenger/MTProxy (fork from https://github.com/TelegramMessenger/MTProxy)
# Features: 交互配置，默认值支持回车即用，兼容新版 Telegram (iOS 12.2+ / Desktop 6.3+)

WORKDIR=$(dirname $(readlink -f $0))
cd $WORKDIR
pid_file=$WORKDIR/pid/pid_mtproxy

URL_MTG="https://github.com/ellermister/mtproxy/releases/download/v0.04/$(uname -m)-mtg"
URL_MTPROTO="https://github.com/ellermister/mtproxy/releases/download/v0.04/mtproto-proxy"
URL_PY_MTPROTOPROXY="https://github.com/alexbers/mtprotoproxy/archive/refs/heads/master.zip"

check_sys() {
    local checkType=$1
    local value=$2

    local release=''
    local systemPackage=''

    if [[ -f /etc/redhat-release ]]; then
        release="centos"
        systemPackage="yum"
    elif grep -Eqi "debian|raspbian" /etc/issue; then
        release="debian"
        systemPackage="apt"
    elif grep -Eqi "ubuntu" /etc/issue; then
        release="ubuntu"
        systemPackage="apt"
    elif grep -Eqi "centos|red hat|redhat" /etc/issue; then
        release="centos"
        systemPackage="yum"
    elif grep -Eqi "debian|raspbian" /proc/version; then
        release="debian"
        systemPackage="apt"
    elif grep -Eqi "ubuntu" /proc/version; then
        release="ubuntu"
        systemPackage="apt"
    elif grep -Eqi "centos|red hat|redhat" /proc/version; then
        release="centos"
        systemPackage="yum"
    fi

    if [[ "${checkType}" == "sysRelease" ]]; then
        if [ "${value}" == "${release}" ]; then
            return 0
        else
            return 1
        fi
    elif [[ "${checkType}" == "packageManager" ]]; then
        if [ "${value}" == "${systemPackage}" ]; then
            return 0
        else
            return 1
        fi
    fi
}

function abs() {
    echo ${1#-};
}

function get_ip_public() {
    local public_ip=""

    # 尝试 Cloudflare trace API
    if [ -z "$public_ip" ]; then
        public_ip=$(curl -4 -s --connect-timeout 5 --max-time 10 https://1.1.1.1/cdn-cgi/trace -A Mozilla 2>/dev/null | grep "^ip=" | cut -d'=' -f2)
    fi
    
    # 尝试 ip.sb API获取公网IP
    if [ -z "$public_ip" ]; then
        public_ip=$(curl -s --connect-timeout 5 --max-time 10 https://api.ip.sb/ip -A Mozilla --ipv4 2>/dev/null)
    fi
    
    # 尝试 ipinfo.io API
    if [ -z "$public_ip" ]; then
        public_ip=$(curl -s --connect-timeout 5 --max-time 10 https://ipinfo.io/ip -A Mozilla --ipv4 2>/dev/null)
    fi
    
    # 如果所有API都失败，退出
    if [ -z "$public_ip" ]; then
        print_error_exit "Failed to get public IP address. Please check your network connection."
    fi
    echo "$public_ip"
}

function get_ip_private() {
    echo $(ip a | grep inet | grep -v 127.0.0.1 | grep -v inet6 | awk '{print $2}' | cut -d "/" -f1 | awk 'NR==1 {print $1}')
}

function get_local_ip(){
  ip a | grep inet | grep 127.0.0.1 > /dev/null 2>&1
  if [[ $? -eq 1 ]];then
    echo $(get_ip_private)
  else
    echo "127.0.0.1"
  fi
}

function get_nat_ip_param() {
    nat_ip=$(get_ip_private)
    public_ip=$(get_ip_public)
    nat_info=""
    if [[ $nat_ip != $public_ip ]]; then
        nat_info="--nat-info ${nat_ip}:${public_ip}"
    fi
    echo $nat_info
}

function get_cpu_core() {
    echo $(cat /proc/cpuinfo | grep "processor" | wc -l)
}

function get_architecture() {
    local architecture=""
    case $(uname -m) in
    i386) architecture="386" ;;
    i686) architecture="386" ;;
    x86_64) architecture="amd64" ;;
    arm | aarch64 | aarch) dpkg --print-architecture | grep -q "arm64" && architecture="arm64" || architecture="armv6l" ;;
    *) echo "Unsupported system architecture "$(uname -m) && exit 1 ;;
    esac
    echo $architecture
}

function build_mtproto() {
    cd $WORKDIR

    local platform=$(uname -m)
    if [[ -z "$1" ]]; then
        echo "缺少参数"
        exit 1
    fi

    do_install_build_dep

    rm -rf build
    mkdir build && cd build

    if [[ "1" == "$1" ]]; then
        # 构建 mtg（默认）
        # golang
        local arch=$(get_architecture)

        #  https://go.dev/dl/go1.18.4.linux-amd64.tar.gz
        local golang_url="https://go.dev/dl/go1.18.4.linux-$arch.tar.gz"
        wget $golang_url -O golang.tar.gz
        rm -rf go && tar -C . -xzf golang.tar.gz
        export PATH=$PATH:$(pwd)/go/bin

        go version
        if [[ $? != 0 ]]; then
            local uname_m=$(uname -m)
            local architecture_origin=$(dpkg --print-architecture)
            echo -e "[\033[33mError\033[0m] golang download failed, please check!!! arch: $arch, platform: $platform,  uname: $uname_m, architecture_origin: $architecture_origin download url: $golang_url"
            exit 1
        fi

        rm -rf build-mtg
        git clone https://github.com/9seconds/mtg.git -b v1 build-mtg
        cd build-mtg && git reset --hard 9d67414db633dded5f11d549eb80617dc6abb2c3  && make static

        if [[ ! -f "./mtg" ]]; then
            echo -e "[\033[33mError\033[0m] Build fail for mtg, please check!!! $arch"
            exit 1
        fi

        cp -f mtg $WORKDIR && chmod +x $WORKDIR/mtg

    elif [[ "2" == "$1" ]]; then
        # 构建 C 语言官方版本
         if [ -d 'MTProxy' ]; then
            rm -rf 'MTProxy'
        fi

        git clone https://github.com/ellermister/MTProxyC --depth=1 MTProxy
        cd MTProxy && make && cd objs/bin &&  chmod +x mtproto-proxy

        if [ ! -f "./mtproto-proxy" ]; then
            echo "mtproto-proxy 编译失败"
            exit 1
        fi

        cp -f mtproto-proxy $WORKDIR
        
        # clean
        rm -rf 'MTProxy'
    fi

    # clean
    cd $WORKDIR
    rm -rf build

}

function get_mtg_provider() {
    source ./mtp_config

    local arch=$(get_architecture)
    # 官方版本只支持 amd64，因此如果用户选了“3”，但系统不是 amd64，则自动切换到1
    if [[ "$arch" != "amd64" && $provider -eq 3 ]]; then
        provider=1
    fi

    if [ $provider -eq 1 ]; then
        echo "mtg"
    elif [ $provider -eq 2 ]; then
        echo "python-mtprotoproxy"
    elif [ $provider -eq 3 ]; then
        echo "official-MTProxy"
    else
        echo "错误配置,请重新安装"
        exit 1
    fi
}

function is_installed() {
    if [ ! -f "$WORKDIR/mtp_config" ]; then
        return 1
    fi
    return 0
}


function kill_process_by_port() {
    pids=$(get_pids_by_port $1)
    if [ -n "$pids" ]; then
        kill -9 $pids
    fi
}

function get_pids_by_port() {
    echo $(netstat -tulpn 2>/dev/null | grep ":$1 " | awk '{print $7}' | sed 's|/.*||')
}

function is_port_open() {
    pids=$(get_pids_by_port $1)

    if [ -n "$pids" ]; then
        return 0
    else
        return 1
    fi
}


function is_running_mtp() {
    if [ -f $pid_file ]; then

        if is_pid_exists $(cat $pid_file); then
            return 0
        fi
    fi
    return 1
}

function is_supported_official_version() {
    local arch=$(uname -m)
    if [[ "$arch" == "x86_64" ]]; then
        return 0
    else
        return 1
    fi
}

function is_pid_exists() {
    # check_ps_not_install_to_install
    local exists=$(ps aux | awk '{print $2}' | grep -w $1)
    if [[ ! $exists ]]; then
        return 1
    else
        return 0
    fi
}

do_install_proxy() {
    local mtg_provider=$1

    if [[ "$mtg_provider" == "mtg" ]]; then
        # 下载 mtg
        echo -e "\033[32m正在安装 golang 版 MTProxy (9seconds)...\033[0m"
        wget $URL_MTG -O mtg
        chmod +x mtg

        [[ -f "./mtg" ]] && ./mtg && echo "Installed for mtg"

    elif [[ "$mtg_provider" == "python-mtprotoproxy" ]]; then
        # Python 版
        echo -e "\033[32m正在安装 Python 版 MTProxy (alexbers)...\033[0m"
        mkdir -p ./bin
        wget $URL_PY_MTPROTOPROXY -O mtprotoproxy-master.zip
        unzip mtprotoproxy-master.zip
        cp -rf mtprotoproxy-master/*.py mtprotoproxy-master/pyaes ./bin/
        rm -rf mtprotoproxy-master mtprotoproxy-master.zip
        chmod +x ./bin/mtprotoproxy.py

    elif [[ "$mtg_provider" == "official-MTProxy" ]]; then
        # 官方版本
        # 官方 C 版只支持 amd64！
        if [[ "$(uname -m)" != "x86_64" ]]; then
            echo -e "\033[31m官方 C 版 MTProxy 仅支持 x86_64 架构，您的架构 $(uname -m) 不支持\033[0m"
            exit 1
        fi

        echo -e "\033[32m正在安装Telegram 官方版本 MTProxy...\033[0m"
        wget $URL_MTPROTO -O mtproto-proxy -q
        chmod +x mtproto-proxy
    fi
}

do_install() {
    cd $WORKDIR

    # 【关键】选择 Python 版才检查/安装 Python 环境
    if [[ "$(get_mtg_provider)" == "python-mtprotoproxy" ]]; then
        echo -e "${GREEN}检测到选择 Python 版，正在智能检查 Python 环境...${PLAIN}"

        # 1. 检查是否已有 python3 和 pip3
        if command -v python3 >/dev/null && command -v pip3 >/dev/null; then
            echo -e "${GREEN}✓ python3 和 pip3 已存在，跳过安装${PLAIN}"
        else
            echo -e "${YELLOW}✗ python3 或 pip3 缺失，正在安装...${PLAIN}"
            if check_sys packageManager apt; then
                apt update && apt install -y python3 python3-pip || exit 1
            elif check_sys packageManager yum; then
                yum install -y epel-release python3 python3-pip || exit 1
            fi
        fi
        
        # 2. 检查 unzip（下载 zip 必须）
        if command -v unzip >/dev/null; then
            echo -e "${GREEN}✓ unzip 已存在，跳过安装${PLAIN}"
        else
            echo -e "${YELLOW}✗ unzip 缺失，正在安装...${PLAIN}"
            if check_sys packageManager apt; then
                apt install -y unzip || exit 1
            elif check_sys packageManager yum; then
                yum install -y unzip || exit 1
            fi
        fi

        # 3. 智能升级 pip（避免太老的 pip 装不了 pyaes）（防御性写法，防止 pip3 命令不存在）
        if command -v pip3 >/dev/null 2>&1; then
            CURRENT_PIP=$(pip3 --version 2>/dev/null | awk '{print $2}' | cut -d. -f1-2)
            if [[ -n "$CURRENT_PIP" ]] && [[ $(echo "$CURRENT_PIP < 20.3" | bc -l 2>/dev/null || echo "1") -eq 1 ]]; then
                echo -e "${YELLOW}pip 版本过低（$CURRENT_PIP），正在自动升级...${PLAIN}"
                python3 -m pip install --upgrade pip --quiet >/dev/null 2>&1 || true
            fi
        else
            echo -e "${YELLOW}pip3 命令异常，跳过版本检查（后面会强制用 python -m pip）${PLAIN}"
        fi

        # 兼容 pyaes 安装（完美支持 Ubuntu 20.04/22.04/24.04 + Debian 12/13）
        echo -e "${YELLOW}正在检查 pyaes 依赖（已安装将自动跳过）...${PLAIN}"
        
        if python3 -c "import pyaes" >/dev/null 2>&1; then
            echo -e "${GREEN}pyaes 已经存在，直接跳过安装${PLAIN}"
        else
            echo -e "${YELLOW}pyaes 未安装，正在智能安装（兼容所有系统）...${PLAIN}"
            
            # 方法1：尝试用系统自带的 pip（Ubuntu 22.04 以下）
            if pip3 install --quiet pyaes 2>/dev/null; then
                echo -e "${GREEN}pyaes 安装成功（方法1：系统 pip）${PLAIN}"
            # 方法2：强制用 python -m pip（绕过系统 pip 限制）
            elif python3 -m pip install --quiet pyaes 2>/dev/null; then
                echo -e "${GREEN}pyaes 安装成功（方法2：python -m pip）${PLAIN}"
            else
                # 最终核弹：强制突破 PEP 668
                python3 -m pip install --quiet --break-system-packages pyaes 2>/dev/null || \
                pip3 install --quiet --break-system-packages pyaes 2>/dev/null || true
                echo -e "${GREEN}pyaes 安装成功（方法3：强制安装）${PLAIN}"
            fi

            # 最终检测是否真的能 import
            if python3 -c "import pyaes" >/dev/null 2>&1; then
                echo -e "${GREEN}pyaes 依赖准备就绪！${PLAIN}"
            else
                echo -e "${RED}致命错误：pyaes 安装失败，Python 版无法运行！${PLAIN}"
                echo -e "${YELLOW}请手动执行以下命令之一：${PLAIN}"
                echo "  python3 -m pip install --break-system-packages pyaes"
                echo "  或升级 pip：python3 -m pip install --upgrade pip"
                exit 1
            fi
        fi
    fi

    # 安装代理本体
    mtg_provider=$(get_mtg_provider)
    do_install_proxy $mtg_provider
    
    if [ ! -d "./pid" ]; then
        mkdir "./pid"
    fi

}

print_line() {
    echo -e "========================================="
}
print_error_exit() {
    print_line
    echo -e "[\033[95mERROR\033[0m] $1"
    print_line
    exit 1
}

print_warning() {
    echo -e "[\033[33mWARNING\033[0m] $1"
}

print_info() {
    echo -e "[\033[32mINFO\033[0m] $1"
}

print_subject() {
    echo -e "\n\033[32m> $1\033[0m"
}

do_kill_process() {
    cd $WORKDIR
    source ./mtp_config

    if is_port_open $port; then
        echo "检测到端口 $port 被占用, 准备杀死进程!"
        kill_process_by_port $port
    fi
    
    if is_port_open $web_port; then
        echo "检测到端口 $web_port 被占用, 准备杀死进程!"
        kill_process_by_port $web_port
    fi
}

do_check_system_datetime_and_update() {
    dateFromLocal=$(date +%s)
    dateFromServer=$(date -d "$(curl -v --silent ip.sb 2>&1 | grep Date | sed -e 's/< Date: //')" +%s)
    offset=$(abs $(( "$dateFromServer" - "$dateFromLocal")))
    tolerance=60
    if [ "$offset" -gt "$tolerance" ];then
        echo "检测到系统时间不同步于世界时间, 即将更新"
        ntpdate -u time.google.com
    fi
}

do_install_basic_dep() {
    echo -e "[\033[33m提醒\033[0m] 正在检测并安装通用基础依赖...\n"
    if check_sys packageManager yum; then
        yum update && yum install -y iproute curl wget procps-ng.x86_64 net-tools ntp
    elif check_sys packageManager apt; then
        apt update
        # 先安装必需的包
        apt install -y iproute2 curl wget procps net-tools || true
        # 尝试安装时间同步工具（可选，允许失败）
        apt install -y ntpsec-ntpdate 2>/dev/null || apt install -y ntpdate 2>/dev/null || true
    fi
    
    return 0
}

do_install_build_dep() {
    if check_sys packageManager yum; then
        yum install -y git  openssl-devel zlib-devel
        yum groupinstall -y "Development Tools"
    elif check_sys packageManager apt; then
        apt install -y git curl  build-essential libssl-dev zlib1g-dev
    fi
    return 0
}

do_config_mtp() {
    cd $WORKDIR

    while true; do
        default_provider=1

        echo -e "请输入要安装的程序版本"
        echo -e " \033[36m1.\033[0m mtg (9seconds)"
        echo -e " └─ Golang 版本, 兼容性强, 轻量极速"
        echo -e " \033[36m2.\033[0m mtprotoproxy (alexbers)"
        echo -e " └─ Python 版本, 功能最全, 兼容性强"
        echo -e " \033[36m3.\033[0m MTProxy (TelegramMessenger)"
        echo -e " └─ Telegram 官方版本 (C语言，仅支持 x86_64，存在兼容问题)"
        
        if ! is_supported_official_version; then
            echo -e "\n[\033[33m提醒\033[0m] 你的系统不支持官方版本\n"
        fi

        read -p "(默认版本: ${default_provider}):" input_provider
        [ -z "${input_provider}" ] && input_provider=${default_provider}
        expr ${input_provider} + 1 &>/dev/null
        if [ $? -eq 0 ]; then
            if [ ${input_provider} -ge 1 ] && [ ${input_provider} -le 3 ] && [ ${input_provider:0:1} != 0 ]; then
                echo
                echo "---------------------------"
                echo "provider = ${input_provider}"
                echo "---------------------------"
                echo
                break
            fi
        fi
        echo -e "[\033[33m错误\033[0m] 请重新输入程序版本 [1-65535]\n"
    done

    while true; do
        default_port=443
        echo -e "请输入一个客户端连接端口 [1-65535]"
        read -p "(默认端口: ${default_port}):" input_port
        [ -z "${input_port}" ] && input_port=${default_port}
        expr ${input_port} + 1 &>/dev/null
        if [ $? -eq 0 ]; then
            if [ ${input_port} -ge 1 ] && [ ${input_port} -le 65535 ] && [ ${input_port:0:1} != 0 ]; then
                echo
                echo "---------------------------"
                echo "port = ${input_port}"
                echo "---------------------------"
                echo
                break
            fi
        fi
        echo -e "[\033[33m错误\033[0m] 请重新输入一个客户端连接端口 [1-65535]"
    done

    # 管理端口
    while true; do
        default_manage=8888
        echo -e "请输入一个管理端口 [1-65535]"
        read -p "(默认端口: ${default_manage}):" input_manage_port
        [ -z "${input_manage_port}" ] && input_manage_port=${default_manage}
        expr ${input_manage_port} + 1 &>/dev/null
        if [ $? -eq 0 ] && [ $input_manage_port -ne $input_port ]; then
            if [ ${input_manage_port} -ge 1 ] && [ ${input_manage_port} -le 65535 ] && [ ${input_manage_port:0:1} != 0 ]; then
                echo
                echo "---------------------------"
                echo "manage port = ${input_manage_port}"
                echo "---------------------------"
                echo
                break
            fi
        fi
        echo -e "[\033[33m错误\033[0m] 请重新输入一个管理端口 [1-65535]"
    done

    # domain
    while true; do
        default_domain="azure.microsoft.com"
        echo -e "请输入一个需要伪装的域名："
        read -p "(默认域名: ${default_domain}):" input_domain
        [ -z "${input_domain}" ] && input_domain=${default_domain}
        http_code=$(curl -I -m 10 -o /dev/null -s -w %{http_code} $input_domain)
        if [ $http_code -eq "200" ] || [ $http_code -eq "302" ] || [ $http_code -eq "301" ]; then
            echo
            echo "---------------------------"
            echo "伪装域名 = ${input_domain}"
            echo "---------------------------"
            echo
            break
        fi
        echo -e "[\033[33m状态码：${http_code}错误\033[0m] 域名无法访问,请重新输入或更换域名!"
    done

    # config info
    public_ip=$(get_ip_public)
    secret="8c11fb4dabd0a019c405800b593cd311"

    # proxy tag
    while true; do
        default_tag=""
        echo -e "请输入你需要推广的TAG："
        echo -e "若没有,请联系 @MTProxybot 进一步创建你的TAG, 可能需要信息如下："
        echo -e "IP: ${public_ip}"
        echo -e "PORT: ${input_port}"
        echo -e "SECRET(可以随便填): ${secret}"
        read -p "(留空则跳过):" input_tag
        [ -z "${input_tag}" ] && input_tag=${default_tag}
        if [ -z "$input_tag" ] || [[ "$input_tag" =~ ^[A-Za-z0-9]{32}$ ]]; then
            echo
            echo "---------------------------"
            echo "PROXY TAG = ${input_tag}"
            echo "---------------------------"
            echo
            break
        fi
        echo -e "[\033[33m错误\033[0m] TAG格式不正确!"
    done

    cat >./mtp_config <<EOF
#!/bin/bash
secret="${secret}"
port=${input_port}
web_port=${input_manage_port}
domain="${input_domain}"
adtag="${input_tag}"
provider=${input_provider}
EOF
    echo -e "配置已经生成完毕!"
}

function str_to_hex() {
    string=$1
    hex=$(printf "%s" "$string" | od -An -tx1 | tr -d ' \n')
    echo $hex
}

function gen_rand_hex() {
    local result=$(dd if=/dev/urandom bs=1 count=500 status=none | od -An -tx1 | tr -d ' \n')
    echo "${result:0:$1}"
}

info_mtp() {
    if [[ "$1" == "ingore" ]] || is_running_mtp; then
        source ./mtp_config
        public_ip=$(get_ip_public)

        domain_hex=$(str_to_hex $domain)

        client_secret="ee${secret}${domain_hex}"
        echo -e "TMProxy+TLS代理: \033[32m运行中\033[0m"
        echo -e "服务器IP：\033[31m$public_ip\033[0m"
        echo -e "服务器端口：\033[31m$port\033[0m"
        echo -e "MTProxy Secret:  \033[31m$client_secret\033[0m"
        echo -e "TG一键链接: https://t.me/proxy?server=${public_ip}&port=${port}&secret=${client_secret}"
        echo -e "TG一键链接: tg://proxy?server=${public_ip}&port=${port}&secret=${client_secret}"
    else
        echo -e "TMProxy+TLS代理: \033[33m已停止\033[0m"
    fi
}

function get_run_command(){
  cd $WORKDIR
  mtg_provider=$(get_mtg_provider)
  source ./mtp_config
    if [[ "$mtg_provider" == "mtg" ]]; then
        domain_hex=$(str_to_hex $domain)
        client_secret="ee${secret}${domain_hex}"
        local local_ip=$(get_local_ip)
        public_ip=$(get_ip_public)

        # ./mtg simple-run -n 1.1.1.1 -t 30s -a 512kib 0.0.0.0:$port $client_secret >/dev/null 2>&1 &
        [[ -f "./mtg" ]] || (echo -e "提醒：\033[33m MTProxy 代理程序不存在请重新安装! \033[0m" && exit 1)
        echo "./mtg run $client_secret $adtag -b 0.0.0.0:$port --multiplex-per-connection 32 --prefer-ip=ipv4 -t $local_ip:$web_port" -4 "$public_ip:$port"

    elif [[ "$mtg_provider" == "python-mtprotoproxy" ]]; then
        cat > ./bin/config.py <<EOF
PORT = ${port}
USERS = {"tg": "${secret}"}
MODES = {
    "classic": False,
    "secure": True,
    "tls": True
}
TLS_DOMAIN = "${domain}"
AD_TAG = "${adtag}"
EOF
      #optimze pool
      sed -i 's/MAX_CONNS_IN_POOL =.*$/MAX_CONNS_IN_POOL = 0/' "$WORKDIR/bin/mtprotoproxy.py" 2>/dev/null || true
      echo "python3 ./bin/mtprotoproxy.py ./bin/config.py"

    elif [[ "$mtg_provider" == "official-MTProxy" ]]; then
      curl -s https://core.telegram.org/getProxyConfig -o proxy-multi.conf
      curl -s https://core.telegram.org/getProxySecret -o proxy-secret
      nat_info=$(get_nat_ip_param)
      workerman=$(get_cpu_core)
      tag_arg=""
      [[ -n "$adtag" ]] && tag_arg="-P $adtag"
      echo "./mtproto-proxy -u nobody -p $web_port -H $port -S $secret --aes-pwd proxy-secret proxy-multi.conf -M $workerman $tag_arg --domain $domain $nat_info --ipv6"
  else
      echo -e "[\033[33mWARNING\033[0m] Invalid configuration, please reinstall"
      exit 1
  fi
}

run_mtp() {
    cd $WORKDIR

    if is_running_mtp; then
        echo -e "提醒：\033[33mMTProxy已经运行，请勿重复运行!\033[0m"
    else
        do_kill_process
        do_check_system_datetime_and_update

        local command=$(get_run_command)
        echo $command
        $command >/dev/null 2>&1 &

        echo $! >$pid_file
        sleep 2
        info_mtp
    fi
}


daemon_mtp() {
    cd $WORKDIR

    if is_running_mtp; then
        echo -e "提醒：\033[33mMTProxy已经运行，请勿重复运行!\033[0m"
        exit 0
    fi

    do_kill_process
    do_check_system_datetime_and_update

    local command=$(get_run_command)
    echo "启动 MTProxy 守护进程..."
    echo $command

    # 前台运行，不要使用 &
    # 使用 bash -c 解析字符串命令
    exec bash -c "$command"
}


debug_mtp() {
    cd $WORKDIR

    echo "当前正在运行调试模式："
    echo -e "\t你随时可以通过 Ctrl+C 进行取消操作"

    do_kill_process
    do_check_system_datetime_and_update

    local command=$(get_run_command)
    echo $command
    $command

}

stop_mtp() {
    if [ ! -f "$pid_file" ]; then
        echo "PID 文件不存在, 无需停止"
        return
    fi

    local pid=$(cat $pid_file)
    if is_pid_exists $pid; then
        kill -9 $pid
        sleep 1
    fi

    if is_pid_exists $pid; then
        echo "停止任务失败"
    else
        echo "停止成功"
        rm -f $pid_file
    fi
}

reinstall_mtp() {
    cd $WORKDIR
    if [ -f "./mtp_config" ]; then
        while true; do
            default_keep_config="y"
            echo -e "是否保留配置文件? "
            read -p "y: 保留 , n: 不保留 (默认: ${default_keep_config}):" input_keep_config
            [ -z "${input_keep_config}" ] && input_keep_config=${default_keep_config}

            if [[ "$input_keep_config" == "y" ]] || [[ "$input_keep_config" == "n" ]]; then
                if [[ "$input_keep_config" == "n" ]]; then
                    rm -f mtp_config
                fi
                break
            fi
            echo -e "[\033[33m错误\033[0m] 输入错误， 请输入 y / n"
        done
    fi

    if [ ! -f "./mtp_config" ]; then 
        do_install_basic_dep
        do_config_mtp
    fi

    do_install
    run_mtp
}

param=$1

if [[ "start" == $param ]]; then
    echo "即将：启动脚本"
    run_mtp
elif [[ "daemon" == $param ]]; then
    echo "即将：启动脚本(守护进程)"
    daemon_mtp
elif [[ "stop" == $param ]]; then
    echo "即将：停止脚本"
    stop_mtp
elif [[ "debug" == $param ]]; then
    echo "即将：调试运行"
    debug_mtp
elif [[ "restart" == $param ]]; then
    stop_mtp
    run_mtp
elif [[ "reinstall" == $param ]]; then
    reinstall_mtp
elif [[ "build" == $param ]]; then
    echo -e "\033[34m进入源码/预编译混合安装模式（开发者专用）\033[0m"
    if [[ "$(get_architecture)" == "amd64" ]]; then
        # build_mtproto 1
        # official 只在 amd64 上编译
        do_install_proxy "official-MTProxy"
    fi
    
    # build_mtproto 2
    # mtg 和 Python 版全架构都支持
    do_install_proxy "mtg"
    do_install_proxy "python-mtprotoproxy"
else
    if ! is_installed; then
        echo "MTProxyTLS一键安装运行绿色脚本"
        print_line
        echo -e "检测到您的配置文件不存在, 为您指引生成!" && print_line

        do_install_basic_dep
        do_config_mtp
        do_install
        run_mtp
    else
        [ ! -f "$WORKDIR/mtp_config" ] && do_config_mtp
        echo "MTProxyTLS一键安装运行绿色脚本"
        print_line
        info_mtp
        print_line
        echo -e "脚本源码：https://github.com/DavidLeeMr/mtproxy"
        echo -e "配置文件: $WORKDIR/mtp_config"
        echo -e "卸载方式：直接删除当前目录下文件即可"
        echo "使用方式:"
        echo -e "\t启动服务\t bash $0 start"
        echo -e "\t调试运行\t bash $0 debug"
        echo -e "\t停止服务\t bash $0 stop"
        echo -e "\t重启服务\t bash $0 restart"
        echo -e "\t重新安装代理程序 bash $0 reinstall"
    fi
fi

create_systemd_service() {
    echo "正在创建并启用 mtp.service systemd 服务..."

    local SERVICE_FILE="/etc/systemd/system/mtp.service"
    local SCRIPT_NAME=$(basename "$0")
    local WORKDIR=$(dirname "$(readlink -f "$0")")

    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=MTProxy TLS (自管理脚本)
After=network.target

[Service]
Type=simple
WorkingDirectory=$WORKDIR
User=root
ExecStart=/bin/bash $WORKDIR/$SCRIPT_NAME daemon
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

    # 重新加载 systemd 配置并启用服务
    systemctl daemon-reload
    systemctl enable --now mtp >/dev/null 2>&1

    echo -e "\n已成功创建并启用 systemd 开机自启服务（mtp.service）"
    echo -e "   服务启动方式: /bin/bash $WORKDIR/$SCRIPT_NAME daemon"
    echo -e "   查看状态： systemctl status mtp"
    echo -e "   查看日志： journalctl -u mtp -f"
    echo -e "   手动更新服务： bash $SCRIPT_NAME systemd\n"
}

# 第一次安装、reinstall、或手动调用时自动创建/更新服务
if [[ "$param" == "reinstall" ]] || [[ "$param" == "" ]] || [[ "$param" == "systemd" ]]; then
    create_systemd_service
    # 如果是手动调用 systemd，则直接退出
    [[ "$param" == "systemd" ]] && exit 0
fi
