from flask import Blueprint, render_template, request
import requests, re

import plotly.express as px
import pandas as pd

import plotly.graph_objects as go

make_graph = Blueprint('make_graph', __name__)

@make_graph.route('/graph', methods=['GET', 'POST'])
def graph():
  
  if request.method == 'POST':
    # フォームから年月の入力を取得
    start_year = request.form['start_year']
    start_month = request.form['start_month']
    end_year = request.form['end_year']
    end_month = request.form['end_month']

    url = 'https://jvndb.jvn.jp/myjvn'
    params = {'method':'getStatistics','feed':'hnd','theme':'sumCvss','type':'m','datePublicStartY':start_year,'datePublicStartM':start_month,'datePublicEndY':end_year,'datePublicEndM':end_month}
    response = requests.get(url,params=params)
    response_text = response.text

    pattern = '<mjstat:resData date="(\d{4}-\d\d)" cntAll="(\d+?)" cntC="(\d+?)" cntH="(\d+?)" cntM="(\d+?)" cntL="(\d+?)" cntN="(\d+?)"/>'
    # findall 
    results = re.findall(pattern, response_text)

    years = []
    total = []
    cvss_C = []
    cvss_H = []
    cvss_M = []
    cvss_L = []
    cvss_N = []
    for a, b, c, d, e, f, g in results:
        years.append(a)
        total.append(int(b))
        cvss_C.append(int(c))
        cvss_H.append(int(d))
        cvss_M.append(int(e))
        cvss_L.append(int(f))
        cvss_N.append(int(g))

    # データをDataFrameに変換
    data = {'年月': years, '脆弱性報告数': total}
    df = pd.DataFrame(data)

    # 折れ線グラフを作成
    fig = px.line(df, x='年月', y='脆弱性報告数', title=f'{start_year}年{start_month}月から{end_year}年{end_month}月までの脆弱性報告数', markers=True)

    fig.update_layout(
        yaxis_title='脆弱性報告数'  # y軸のラベルを設定
    )

    # グラフをHTMLに変換
    graph_html = fig.to_html(full_html=False)
#ここまでが上のグラフ

#ここからが下のグラフ
    start_year_int = int(start_year)
    start_month_int = int(start_month)
    end_year_int = int(end_year)
    end_month_int = int(end_month) + 1
    # 指定した範囲内のデータ
    date_range = pd.date_range(start=f'{start_year_int}-{start_month_int:02d}', end=f'{end_year_int}-{end_month_int:02d}', freq='M')

    data = {
        'Date': date_range,
        '緊急': cvss_C[:len(date_range)],
        '重要': cvss_H[:len(date_range)],
        '警告': cvss_L[:len(date_range)],
        '注意': cvss_M[:len(date_range)],
        'なし意': cvss_N[:len(date_range)]
    }
    df = pd.DataFrame(data)

    fig_line = go.Figure()
    # グラフの作成（4つのデータセットを同じグラフに表示）
    for column_name in ['緊急', '重要', '警告', '注意', 'なし意']:
      fig_line.add_trace(
         go.Scatter(
            x=df['Date'],
            y=df[column_name],
            mode='lines+markers',
            name=column_name
         )
      )

    fig_line.update_layout(
      title=f'{start_year}年{start_month}月から{end_year}年{end_month}月までの脅威度別脆弱性報告数',
      xaxis_title='年月',
      yaxis_title='脆弱性報告数',
      hovermode='x'
    )

    graph_line = fig_line.to_html(full_html=False)
    #ここまでが下のグラフ

    return render_template('graph.html', graph_html=graph_html, graph_line=graph_line, 
                           start_year=start_year, start_month=start_month, end_year=end_year, end_month=end_month)

  return render_template('graph.html')