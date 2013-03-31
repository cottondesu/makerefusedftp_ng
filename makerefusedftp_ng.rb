#定数読み込み
require './makerefusedftp_const'
include MakerefusedftpConst

class LogAnalyze

  def initialize()
    @logs = []
    @count_targets = []
    @sums = []

    #ログ抽出
    extract()
    #重複IPの集計
    repetitionip_count()

  end

  #----------------------------------
  # loginを取得する
  #----------------------------------
  def get_login(line)
    mon = line.slice(4,3)
    date = line.slice(8,2)
    time = line.slice(11,8)    

    return mon + " " + date + " " + time
  end

  #-------------------------------------
  #ログから FAIL LOGIN: Client をキーに   
  #該当する行を抽出する
  #-------------------------------------
  def extract
    if LOGNAME =~ /vsftpd.log/
      File::open(LOGNAME){|f|
        while text = f.gets
          if text =~ /FAIL LOGIN: Client/
            (str_top,str_tail) = text.split(/ FAIL LOGIN: Client /)
            str_tail = str_tail.chomp
            (top_left,top_right) = str_top.split(/ \[pid /)
            (r_left,str_user) = top_right.split(/ /)

            login = get_login(top_left)

            str_user = "unknown" if str_user.empty?
            
            if ((str_user !~ /^127.0.0/) && (str_user !~ /^$SELFLAN/)) 
              @logs << {:date=>login, :addr=>str_tail.gsub(/\"/,""),
                        :info=>str_user.gsub(/(\[|\])/, "")}
            end
          end
        end
      }
    end
  end

  #----------------------------------
  # 一意のIP配列作成
  #----------------------------------
  def uniqip_array()
    @logs.map { |log|
      log[:addr]
    }.uniq
  end

  #----------------------------------
  # vsftpd.logから重複するIPを集計
  #----------------------------------
  def repetitionip_count()
    @count_targets = uniqip_array()
    @count_targets.each do | uniqip |
      count = 0
      h = {}
      @logs.each do | vsftpdlog |
        #配列内のIPと比較
        if uniqip == vsftpdlog[:addr]
          count+=1
        end
        h = {:count=>count ,:date=>vsftpdlog[:date] ,
             :addr=>vsftpdlog[:addr] ,:info=>vsftpdlog[:info]}
      end
      @sums.push(h)
    end
  end

  #-----------------------------
  #解析したログを取得する
  #-----------------------------
  def get_log()
    return [@logs,@sums]
  end
end

class MakeHTML

  def initialize()
    set_log(LogAnalyze.new.get_log)
  end

  #-----------------------------------
  #HTMLで出力するログを設定する
  #-----------------------------------
  def set_log(log)
    (@vsftpdlogs,@repetitionips) = log
    @repetitionips.sort!
  end

  #-----------------------------------
  #不正アクセスのIPカウント、日付、IPを
  #HTMLで出力
  #-----------------------------------
  def repetitionip_output(f)
    @repetitionips = @repetitionips[0,SUMTOP]
    @repetitionips.each_with_index do | repetitionip , index |
      count = sprintf("%4d",repetitionip[:count])
      f.print <<-"EOM"
              <TR>
                <TD align="right">#{index + 1}</TD>
                <TD align="right">#{count}</TD>
                <TD>#{repetitionip[:date]}</TD>
                <TD>#{repetitionip[:addr]}</TD>
                <TD>#{repetitionip[:info]}</TD>
              </TR>
      EOM
    end
  end

  #-----------------------------------
  #不正アクセスのIPの履歴を
  #HTMLで出力
  #-----------------------------------
  def attackip_history(f)
    @vsftpdlogs = @vsftpdlogs[0,HISTORYTOP]
    @vsftpdlogs.each_with_index do | vsftpdlog , index |
      f.print <<-"EOM"
                <TR>
                  <TD align="right">#{index + 1}</TD>
                  <TD>#{vsftpdlog[:date]}</TD>
                  <TD>#{vsftpdlog[:addr]}</TD>
                  <TD>#{vsftpdlog[:info]}</TD>
                </TR>
      EOM
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
      repetitionip_output(f)

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
      attackip_history(f)

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

#-----------------------------
#メイン部
#-----------------------------
def main()
  #HTML作成クラス　HTML出力
  MakeHTML.new().output
end

main()