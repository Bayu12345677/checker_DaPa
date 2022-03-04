#!/bin/bash


# author : polygon
# bash vers : 5.1
# tools : da pa checker

# bash moderen
. lib/moduler.sh

# depencies
Bash.import: util/IO.FUNC util/io.class
Bash.import: util/pipe urlib/urlparser
Bash.import: fake_useragent/HTTP.UA util/tryCatch

Namespace: da_pa.sh
{
  # warna
  bi=$(mode.bold: biru)    cy=$(mode.bold: cyan)
  ij=$(mode.bold: hijau)  hi=$(mode.normal: hitam)
  me=$(mode.bold: merah)  un=$(mode.bold: ungu)
  ku=$(mode.bold: kuning) pu=$(mode.bold: putih)
  m=$(mode.bold: pink)    st=$(default.color)

  class req;
  {
    public: app = da
    public: app = pa
    public: app = links

    # object pa
    def: req::pa(){
      global: url = "$@"

      headers=(
        "Host: w3seotools.com"
        "content-length: 24"
        "cache-control: max-age=0"
        'sec-ch-ua: "Google Chrome";v="93", " Not;A Brand";v="99", "Chromium";v="93"'
        "sec-ch-ua-mobile: ?1"
        'sec-ch-ua-platform: "Android"'
        "upgrade-insecure-requests: 1"
        "origin: https://w3seotools.com"
        "content-type: application/x-www-form-urlencoded"
        "save-data: on"
        "user-agent: Mozilla/5.0 (Linux; Android 9; TA-1021) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.62 Mobile Safari/537.36"
        "accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"
        "sec-fetch-site: same-origin"
        "sec-fetch-mode: navigate"
        "sec-fetch-user: ?1"
        "sec-fetch-dest: document"
        "referer: https://w3seotools.com/da-pa-checker/"
        "accept-encoding: gzip, deflate, br"
        "accept-language: id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7"
      ); # headers
      # mengambil isi set-cookie
      cookie=$(curl -I -sL -A "$(Bash::Ua.Random)" --tr-encoding --proxy-insecure -H 'sec-ch-ua: "Google Chrome";v="93", " Not;A Brand";v="99", "Chromium";v="93"' https://w3seotools.com/da-pa-checker/ | grep "set-cookie:" | cut -d " " -f2 | sed 's/;/''/g')

      ambil_uri=$(
      curl -sL --tr-encoding \
      -H "${headers[11]}" \
      -H "${headers[10]}" \
      -H "${headers[3]}" \
      -H "cookie: ${cookie}" \
      -X POST --data-urlencode "url=${@}" -d "myButton=" https://w3seotools.com/da-pa-checker/ --insecure --compressed | grep '<p>' | grep "[0-9]" | head -1 | grep -o "[0-9]" | tr -d "\n"
      ); echo "${ambil_uri}"
    }; @ ketik aja curl --help all biar paham opsi -H dan opsi lain nya
      # obj da
        def: req::da(){
                	global: url = "$@"

                	headers=(
                    	    "Host: w3seotools.com"
                        	"content-length: 24"
                        	"cache-control: max-age=0"
                        	'sec-ch-ua: "Google Chrome";v="93", " Not;A Brand";v="99", "Chromium";v="93"'
                        	"sec-ch-ua-mobile: ?1"
                        	'sec-ch-ua-platform: "Android"'
                        	"upgrade-insecure-requests: 1"
                        	"origin: https://w3seotools.com"
                        	"content-type: application/x-www-form-urlencoded"
                        	"save-data: on"
                        	"user-agent: Mozilla/5.0 (Linux; Android 9; TA-1021) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.62 Mobile Safari/537.36"
                        	"accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"
                        	"sec-fetch-site: same-origin"
                        	"sec-fetch-mode: navigate"
                        	"sec-fetch-user: ?1"
                        	"sec-fetch-dest: document"
                        	"referer: https://w3seotools.com/da-pa-checker/"
                        	"accept-encoding: gzip, deflate, br"
                        	"accept-language: id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7"
                	); # headers
          # data request nya
                	global: data = "url=${url}&myButton="
          # untuk mengambil isi dari set-cookie
                	cookie=$(curl -I -sL -A "$(Bash::Ua.Random)" --tr-encoding --proxy-insecure -H 'sec-ch-ua: "Google Chrome";v="93", " Not;A Brand";v="99", "Chromium";v="93"' https://w3seotools.com/da-pa-checker/ | grep "set-cookie:" | cut -d " " -f2 | sed 's/;/''/g')

                	ambil_uri=$(
                	curl -sL --tr-encoding \
                  -H "${headers[10]}" \
    	            -H "${headers[3]}" \
        	        -H "cookie: ${cookie}" \
            	    -X POST --data-urlencode "url=${@}" -d "myButton=" https://w3seotools.com/da-pa-checker/ --insecure --compressed | grep '</p>' | grep "[0-9]" | head -1 | grep -o "[0-9]" | tr -d "\n"
                	); echo "${ambil_uri}"
        	};
        	# obj links
        def: req::links(){
                	global: url = "$@"

                  headers=(
    	                    "Host: w3seotools.com"
        	                "content-length: 24"
            	            "cache-control: max-age=0"
                	        'sec-ch-ua: "Google Chrome";v="93", " Not;A Brand";v="99", "Chromium";v="93"'
                    	    "sec-ch-ua-mobile: ?1"
                        	'sec-ch-ua-platform: "Android"'
                          "upgrade-insecure-requests: 1"
    	                    "origin: https://w3seotools.com"
        	                "content-type: application/x-www-form-urlencoded"
            	            "save-data: on"
                	        "user-agent: Mozilla/5.0 (Linux; Android 9; TA-1021) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.62 Mobile Safari/537.36"
                    	    "accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"
                        	"sec-fetch-site: same-origin"
                          "sec-fetch-mode: navigate"
    	                    "sec-fetch-user: ?1"
        	                "sec-fetch-dest: document"
            	            "referer: https://w3seotools.com/da-pa-checker/"
                	        "accept-encoding: gzip, deflate, br"
                    	    "accept-language: id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7"
                  ); # headers

          # data params nya
        	        global: data = "url=${url}&myButton="
          # untuk mengambil set-cookie
                	cookie=$(curl -I -sL -A "$(Bash::Ua.Random)" --tr-encoding --proxy-insecure -H 'sec-ch-ua: "Google Chrome";v="93", " Not;A Brand";v="99", "Chromium";v="93"' https://w3seotools.com/da-pa-checker/ | grep "set-cookie:" | cut -d " " -f2 | sed 's/;/''/g')

                	ambil_uri=$(
                	curl -sL --tr-encoding \
                	-H "${headers[3]}" \
                	-H "cookie: ${cookie}" \
                	-X POST --data-urlencode "url=${@}" -d "myButton=" https://w3seotools.com/da-pa-checker/ --insecure --compressed | grep '</b>' | grep "[0-9]" | head -1 | grep -o "[0-9]" | tr -d "\n"
               	)
            	echo "${ambil_uri}"
        	};

  }; class.new: req respon

  # random warna
  warna=( "${ij}" "${ku}" "${me}" "${b}" "${cy}" "${m}" "${hi}" )

  random=$(shuf -i 0-6 -n 1)
  random2=$(shuf -i 1-5 -n 1)

<<EOF
  BANNER
EOF

  def: banner(){
    echo -e "${warna[$random]}________                            ${warna[$random2]}  ______________            ______"
    echo -e "${warna[$random]}___  __ |_____ _ ______________ _ ${warna[$random2]}   __  ____/__  /_______________  /______________"
    echo -e "${warna[$random]}__  / / /  __ '/ ___  __ |  __ '/ ${warna[$random2]}   _  /    __  __ |  _ |  ___/_  //_/  _ |_  ___/"
    echo -e "${warna[$random]}_  /_/ // /_/ /  __  /_/ / /_/ /  ${warna[$random2]}   / /___  _  / / /  __/ /__ _  ,<  /  __/  /"
    echo -e "${warna[$random]}/_____/ |__,_/  _  .___/|__,_/   ${warna[$random2]}    |____|  /_/ /_/|___/|___/ /_/|_| |___//_/"
    echo -e "${warna[$random]}                /_/${st}"
    Tulis.strN "${ku}----------------------------------------------------${st}"
    Tulis.strN "${ku}[${me}•${ij}•${ku}]${pu} Language    : Bash"
    Tulis.strN "${ku}[${me}•${ij}•${ku}]${pu} tools       : checker da pa"
    Tulis.strN "${ku}[${me}•${ij}•${ku}]${pu} dorkmachine : Lynx"
    Tulis.strN "${ku}---------------------------------------------------${st}"
    Tulis.strN "${ku}[${me}!${ku}]${pu} Author : Polygon"
    Tulis.strN "${ku}[${me}!${ku}]${pu} github : Bayu12345677"
    Tulis.strN "${ku}[${me}!${ku}]${pu} Team   : gak punya"
    Tulis.strN "${ku}---------------------------------------------------${st}\n"
    Tulis.strN "${ku}[${me}•${ij}•${ku}]${pu} masukan list dork atau list target"
    Tulis.str "${ku}[${me}•${ij}•${ku}]${ij}-${m}>${st} "
  }

  # animations loop text run
    def: sys.text(){
      text="$@"
      for x in {0..1}; do
        for ((i = 0; i < ${#text}; i++)); do
          printf "\r${text:0:i+1}"
          sleep 0.01
        done
      done
    };

    class runner;
    {
      public: app = text

      def: runner::text(){
        Text="$@"

        var value : 0
        var count : $(echo "$Text" | wc -l)
        while ((value<=count)); do
          let value++
          var value_frame : $(echo "$Text" | tail +${value} | head -1)
          sys.text "$value_frame"; echo
        done
      }
    }; class.new: runner run

  # google search
  def: go_finder(){
    var COUNT : 0
    while [ "$COUNT" -le 250 ];
    do
      lynx "http://www.google.com/search?q=$1&start=$COUNT" -dump -listonly | grep 'url?q=' | cut -d ' ' -f4 | sed 's/http:\/\/www.google.com\/url?q=//' | sed 's/\(&sa=\).*//' | sed -f modules/urldecode.sed | sort | uniq
      COUNT=$(( $COUNT +10 ))
    done
  }

  # machine serach bing
  def: machine(){
    global: cari = "$1"
    var COUNT : 0
    while [ "$COUNT" -le 225 ]; do
      lynx "http://www.bing.com/search?q=${cari}&qs=n&pq=${cari}&sc=8-5&sp=-1&sk=&first=$COUNT&FORM=PORE" -dump -listonly
      COUNT=$((COUNT +12))
    done
  }

  # membersihkan hasil dari mesin pencarian
  def: cleaner(){
    var files : "$1"
    cat "$files" | \
            grep -v 'http://www.bing.com' | \
            grep -v 'javascript:void' | \
            grep -v 'javascript:' | \
            grep -v 'Hidden links:' | \
            grep -v 'Visible links' | \
            grep -v 'References' | \
            grep -v 'msn.com' | \
            grep -v 'microsoft.com' | \
            grep -v 'yahoo.com' | \
            grep -v 'live.com' | \
            grep -v 'microsofttranslator.com' | \
            grep -v 'irongeek.com' |
            grep -v 'hackforums.net' | \
            grep -v 'freelancer.com' | \
            grep -v 'facebook.com' | \
            grep -v 'mozilla.org' | \
            grep -v 'stackoverflow.com' | \
            grep -v 'php.net' | \
            grep -v 'wikipedia.org' | \
            grep -v 'amazon.com' | \
            grep -v '4shared.com' | \
            grep -v 'wordpress.org' | \
            grep -v 'about.com' | \
            grep -v 'phpbuilder.com' | \
            grep -v 'phpnuke.org' | \
            grep -v 'youtube.com' | \
            grep -v 'p4kurd.com' | \
            grep -v 'tizag.com' | \
            grep -v 'devshed.com' | \
            grep -v 'owasp.org' | \
            grep -v 'fictionbook.org' | \
            grep -v 'silenthacker.do.am' | \
            grep -v 'codingforums.com' | \
            grep -v 'tudosobrehacker.com' | \
            grep -v 'zymic.com' | \
            grep -v 'gaza-hacker.com' | \
            grep -v 'immortaltechnique.co.uk' | \
            cut -d' ' -f4 | \
            sed -f modules/urldecode.sed | \
            sed '/^$/d' | \
            sed 's/9.//' | \
            sed '/^$/d' | \
            sort | \
            uniq
  }

  def: main(){
    clear; banner
    read target
    	echo

    # validasi input target
    if [[ -z "$target" ]]; then
      println_info " input gak boleh kosong\n"
      exit 2
    fi;

    # cek files
    if [[ ! -f "$target" ]]; then
      println_info " list not found (list tidak di temukan)\n"
      exit 2
    fi

    # cek isi files
    isi=$(cat $target|head -1)
    if ! (curl -sL "$isi" &> /dev/null); then @ jika isi dari list bukan alamat url maka akan menganggap nya sebagai dork dan sebalik nya
      println_info " memulai dork\n"
      for dork in $(cat $target); do
        machine "$dork" >> $stored_tmp
      done
        hasil=$(echo "$(cleaner $stored_tmp)")

        for checker in $(echo "$hasil"); do
          urlregex=$(echo "$checker" | urlparser% to hostname | tr -d '"'); @ site yg saya gunakan untuk checker alamat url hanya support sama domain doang kebanyakan hasil berisikan (protocol domain path) maka saya ambil domain nya saja
          da=$(respon.da $urlregex); @ checker da
          pa=$(respon.pa $urlregex); @ checker pa
          lenks=$(respon.links $urlregex); @ checker link dari alamat url
          # cetak ke layar utama
          println_info " $urlregex ${ku}-${ij}>${st} ${ku}[${pu}da${me}:${pu}${da}${ku}] [${pu}pa${me}:${pu}${pa}${ku}] [${pu}link${me}:${pu}${lenks}${ku}]${st}"
          echo " $urlregex -> [da : ${da}] [pa : ${pa}] [link : ${lenks}]" >> found.txt
        done; Tulis.strN "\n${ku}[${ij}√${ku}]${pu} process has been completed"
        Tulis.strN "${ku}[${ij}√${ku}]${pu} found ${me}$(cat found.txt | wc -l)${st}\n"; exit 2
        rm -rf "$stored_tmp"
       	else
       			println_info " start checker da pa\n"
       			for checker in $(cat $target); do
       				urlregex=$(echo "$checker" | urlparser% to hostname | tr -d '"'); @ system nya sama seperti di atas saran saya untuk ke akuratan sebaik nya kalian menggunakan list target yg berisikan (protocol://domain/path) agar mudah di parse oleh system sumber script ini
       				da=$(respon.da "${urlregex}"); @ checker da
       				pa=$(respon.pa "${urlregex}"); @ checker pa
       				lenks=$(respon.links "${urlregex}"); @ checker link dari alamat url
       				println_info " $urlregex ${ku}-${ij}>${st} ${ku}[${pu}da${me}:${pu}${da}${ku}] [${pu}pa${me}:${pu}${pa}${ku}] [${pu}link${me}:${pu}${lenks}${ku}]${st}"
       				echo " $urlregex -> [da : ${da}] [pa : ${pa}] [link : ${lenks}]" >> found.txt;
       			done; echo
       				Tulis.strN "${ku}[${ij}√${ku}]${pu} process has been completed"
       				Tulis.strN "${ku}[${ij}√${ku}]${pu} result in save in found.txt\n"
       		fi;
  };

  def: sys.trap(){
    echo
    println_info " triggered sigint signal"
    println_info " out of tools"
    if [[ $(cat DATA_LOGIN.tmp) == 15 ]]; then
      echo "15"> DATA_LOGIN.tmp
    fi
    rm -rf ${stored_tmp}
    echo; exit $?
  }
    stored_tmp=$(mktemp -t storage_tmp.$$.XXX)
    data_users=$(echo "DATA_LOGIN.tmp")
    trap "sys.trap" INT SIGINT

    re=$(cat $data_users);
    echo $((re += 1)) > $data_users
    var::command data_use = cat $data_users
      if test "$data_use" == "15"; then
    function kata {
      Tulis.strN "${ku}[${me}•${ku}]${pu} Author : Bayu riski A.M (polygon)"
      Tulis.strN "${ku}[${me}•${ku}]${pu} github : Bayu12345677\n"
      Tulis.strN "\t${ij}[${st} tanks been using my tools ${ij}]${st}\n"
      Tulis.strN "apakah anda puas dengan karya kami ?"
      Tulis.strN "jika anda puas beri kami tombol subscribe :)"
    }; run.text "$(kata)"
      sleep 2s
      xdg-open https://youtube.com/channel/UCtu-GcxKL8kJBXpR1wfMgWg
      read -p "apakah anda puas : " m
      echo "0" > $data_users
    fi
   @ maintance system
  var versi : $(cat files/vers.txt)
  var git : $(curl -sL https://raw.githubusercontent.com/Bayu12345677/checker_DaPa/main/files/vers.txt)

  if [[ $git == $versi ]]
  then
  	dummy=
    @ halo world
  else
    read -p "this version of the script has been a long time, please update this script immediately: " m
      cd ../
      rm -rf checker_DaPa/
      git clone https://github.com/Bayu12345677/checker_DaPa/
      echo
      Tulis.strN "${ku}[${me}!${ku}]${st} please run command cd. To update the contents of this derectory\n"
      exit
  fi
    # run
    var this : $(IO.func)

    try {
      $this.NAME main && main
    } catch {
      main
    }
};
