TITLE = 'FTP不正アクセス一覧'
#ローカルIP
SELFLAN = '192.168.24'
#集計の表示件数
SUMTOP = 20
#履歴の表示件数
HISTORYTOP = 50
#コマンドラインからのログ名
LOGNAME = ARGV[0]
#出力ファイル名
OUTHTML = 'refusedftp_ng.html'
#テーブルの色
TBLBKCOL = '#EEEE00'

VER = "1.0"

class LogAnalyze

  def initialize
    @logs = []
    @countTargets = []
    @sums = []
  end

  #----------------------------------
  # loginを取得する
  #----------------------------------
  def getLogin(line)
    mon = line.slice(4,3)
    date = line.slice(8,2)
    time = line.slice(11,8)    

    return mon + " " + date + " " + time
  end

  #-------------------------------------
  #ログから FAIL LOGIN: Client をキーに   
  #該当する行を抽出する                   
  #@return logs:抽出した行配列            
  #-------------------------------------
  def extract
    File::open(LOGNAME){|f|
      if LOGNAME =~ /vsftpd.log/ 
        while text = f.gets
          if text =~ /FAIL LOGIN: Client/
            (strtop,strtail) = text.split(/ FAIL LOGIN: Client /)
            strtail = strtail.chomp.gsub(/(\r\n|\r|\n)/, "")
            (topLeft,topRight) = strtop.split(/ \[pid /)
            (rLeft,struser) = topRight.split(/ /)

            struser = struser.gsub(/(\[|\])/, "")
            login = getLogin(topLeft)

            if struser === ""
              struser = "unknown"
            end
            if (($struser !~ /^127.0.0/) && ($struser !~ /^$SELFLAN/)) 
              @logs.push(login + "<>" + strtail + "<>" + struser)
            end
          end
        end
      end
    }

    return @logs
  end



  #----------------------------------
  # 一意のIP配列作成                   
  # @param vsftpdlogs:vsftpdlog      
  #----------------------------------
  def uniqIpArray()
    @logs.each do | vsftpdlog |
      (atackdate,atackip,atackinfo)  = vsftpdlog.split(/<>/)
      atackip = atackip.gsub(/\"/,"")
      @countTargets.push(atackip)
    end
    @countTargets = @countTargets.uniq
  end

  #----------------------------------
  # vsftpd.logから重複するIPを集計     
  # @param uniqIPArrays:一意のIP配列  
  # @param vsftpdlogs:vsftpdlog      
  #----------------------------------
  def repetitionIpCount()
    @countTargets.each do | uniqIP |
      count = 0
      tmpAtackdate =""
      tmpAatackip =""
      tmpAatackinfo =""
      @logs.each do | vsftpdlog |
        (tmpAtackdate,tmpAatackip,tmpAatackinfo)  = vsftpdlog.split(/<>/)
        tmpAatackinfo = tmpAatackinfo.chomp
        tmpAatackip = tmpAatackip.gsub(/\"/,"")
        if uniqIP == tmpAatackip
          count+=1
        end    
      end
      sumline = "#{count}<>#{tmpAtackdate}<>#{tmpAatackip}<>#{tmpAatackinfo}"
      @sums.push(sumline)
    end

    return @sums
  end
end

class MakeHTML

  #-----------------------------------
  #HTMLで出力するログを設定する
  #-----------------------------------
  def setLog(vsftpdlogs,repetitionIps)
    @vsftpdlogs = vsftpdlogs
    @repetitionIps = repetitionIps.sort{ |a,b| a <=> b}
  end

  #-----------------------------------
  #不正アクセスのIPカウント、日付、IPを
  #HTMLで出力
  #-----------------------------------
  def repetitionIpOutput(f)
    @repetitionIps.each_with_index do | repetitionIp , index |
      (count,date,ip,info) = repetitionIp.split(/<>/)
      seqno = index + 1
      count = sprintf("%4d",count)
      f.print <<-"EOM"
              <TR>
                <TD align="right">#{seqno}</TD>
                <TD align="right">#{count}</TD>
                <TD>#{date}</TD>
                <TD>#{ip}</TD>
                <TD>#{info}</TD>
              </TR>
      EOM
      if seqno == SUMTOP
        break
      end
    end
  end

  #-----------------------------------
  #不正アクセスのIPの履歴を
  #HTMLで出力
  #-----------------------------------
  def attackIpHistory(f)
    @vsftpdlogs.each_with_index do | vsftpdlog , index|
      (atackdate,atackip,atackinfo)  = vsftpdlog.split(/<>/)
      atackip = atackip.gsub(/\"/,"")
      seqno = index + 1
      f.print <<-"EOM"
                <TR>
                  <TD align="right">#{seqno}</TD>
                  <TD>#{atackdate}</TD>
                  <TD>#{atackip}</TD>
                  <TD>#{atackinfo}</TD>
                </TR>
      EOM
      if seqno == HISTORYTOP
          break
      end
    end
  end

  def output()
    File::open(OUTHTML,'w'){|f|
      f.print <<-"EOM"
      <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
      <HTML>
      <HEAD>
      <META http-equiv="Content-Type" content="text/html; charset=UTF8">
      <TITLE>#{TITLE}</TITLE>
      </HEAD>
      <TABLE width="98%" cellpadding="0" cellspacing="0">
        <TBODY>
          <TR>
            <TD width="5" rowspan="2" bgcolor="#0000ff" nowrap></TD>
            <TD><B>FTPに不正アクセスをしてきたIPアドレスと回数(TOP #{SUMTOP})</B></TD>
          </TR>
          <TR>
            <TD colspan="2" bgcolor="#0000ff"></TD>
          </TR>
          <TR>
            <TD colspan="2" height="10"></TD>
          </TR>
          <TR>
            <TD colspan="2" height="10"></TD>
          </TR>
          <TR>
            <TD></TD>
            <TD>
              <TABLE bgcolor="#ffffff" border="1" width="100%" cellpadding="2" cellspacing="1">
                <TBODY>
                  <TR bgcolor="#{TBLBKCOL}">
                    <TH rowspan="2">No</TH>
                    <TH colspan="2">Atack</TH>
                    <TH rowspan="2">IP Address</TH>
                    <TH rowspan="2">Etc Infomation</TH>
                  </TR>
                  <TR bgcolor="#{TBLBKCOL}">
                    <TH>Count</TH>
                    <TH>Last</TH>
                  </TR>
      EOM

      #不正アクセスのIPカウント、日付、IPを出力
      repetitionIpOutput(f)

      f.print <<-"EOM"
              </TBODY>
            </TABLE>
          </TD>
        </TR>
        <TR>
          <TD colspan="2" height="10"></TD>
        </TR>
        <TR>
          <TD rowspan="2" bgcolor="#0000ff"></TD>
          <TD><B>FTPに不正アクセスをしてきたIPアドレスの履歴(TOP #{HISTORYTOP})</B></TD>
        </TR>
          <TR>
          <TD bgcolor="#0000ff" height="1"></TD>
        </TR>
        <TR>
          <TD colspan="2" height="10"></TD>
        </TR>
        <TR>
          <TD></TD>
          <TD>
            <TABLE bgcolor="#ffffff" border="1" width="100%" cellpadding="5" cellspacing="1">
              <TBODY>
                <TR bgcolor="#{TBLBKCOL}">
                  <TH nowrap>No</TH>
                  <TH nowrap>Atack Date</TH>
                  <TH nowrap>IP Address</TH>
                  <TH nowrap>Etc Infomation</TH>
                </TR>
      EOM

      #不正アクセスのIP履歴を出力
      attackIpHistory(f)

      f.print <<-"EOM"
                </TBODY>
              </TABLE>
            </TD>
          </TR>
          <TR>
            <TD colspan="2" height="10"></TD>
          </TR>
        </TBODY>
      </TABLE>
      </BODY>
      </HTML>
      EOM
      }
  end
end

#------------- メイン部 -----------------------------------------#

def main()
  #ログ解析クラス
  log = LogAnalyze.new
  #HTML作成クラス
  html = MakeHTML.new

  #ログの解析
  vsftpdlogs = log.extract
  #一意のIP配列作成
  log.uniqIpArray()
  #重複するIPの集計
  repetitionIps = log.repetitionIpCount()
  #出力するログを設定
  html.setLog(vsftpdlogs,repetitionIps)
  #HTML出力
  html.output
end

main()