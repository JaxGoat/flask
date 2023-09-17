from flask import Blueprint, render_template, request, Markup
import requests
import re
import plotly.graph_objs as go

api_search = Blueprint('search', __name__)

@api_search.route("/search")
def search():
    test_data = open("templates/jvndb_2023.rdf", "r", encoding="utf-8")
    contents = test_data.read()
    test_data.close()

    keyword = request.args.get('keyword',default='')
    vendor = request.args.get('vendor',default='')

    #
    if keyword == '' and vendor == '':
        return render_template('index.html')
    
    # https://jvndb.jvn.jp/myjvn?keyword=sudo&feed=hnd&method=getVulnOverviewList&datePublicStartY=2019&rangeDatePublished=n&rangeDateFirstPublished=n
    url = "https://jvndb.jvn.jp/myjvn"
    params = {'keyword':vendor,'feed':'hnd','method':'getVendorList'}
    response = requests.get(url,params=params)
    match = re.search(rf'vname="{vendor}" cpe="[^"]*" vid="(\d+)"', response.text)
    if match:
        vid = match.group(1)
        params = {'keyword':keyword,'feed':'hnd','method':'getVulnOverviewList','datePublicStartY':'2019','rangeDatePublished':'n','rangeDateFirstPublished':'n','vendorId':vid}
    else:
        params = {'keyword':keyword,'feed':'hnd','method':'getVulnOverviewList','datePublicStartY':'2019','rangeDatePublished':'n','rangeDateFirstPublished':'n'}
    response = requests.get(url,params=params)

    cvssv2_list = []
    cvssv3_list = []

    # kaiseki
    items = re.findall(r'<item [^>]*>(.*?)<\/item>', contents, re.DOTALL)
    table = '<table border="1"><tr><th>ID</th><th>title</th><th>CVSSv3</th><th>CVSSv2</th></tr>'
    
    for item in items:
        sec_identifier = re.findall(r'<sec:identifier>(.*?)<\/sec:identifier>', item)
        title = re.findall(r'<title>(.*?)<\/title>', item)
        link = re.findall(r'<link>(.*?)<\/link>', item)
        item_vendor = re.findall(r'vendor="(.*?)"', item)

        cvssv3 = re.findall(r'sec:cvss version="3.0" score="(\d+\.\d+)"', item)
        cvssv2 = re.findall('<sec:cvss score="(\w.?\w?)"\sseverity=".{3,8}"\svector="AV', item, re.S)

        cvssv3 = cvssv3[0] if cvssv3 else "-"
        cvssv2 = cvssv2[0] if cvssv2 else "-"

        sec_identifier = sec_identifier[0] if sec_identifier else "-"

        item_vendor[0] if item_vendor else item_vendor.append('')
        if keyword == '' or keyword in title[0]:
            if vendor == '' or vendor == item_vendor[0]:
                table = table + '<tr><td><a href="'+ link[0] +'">' + sec_identifier + '</a></td><td>' + title[0] + '</td><td>' + cvssv3 + '</td><td>' + cvssv2 + '</td></tr>'
                if cvssv2 != '-':
                     cvssv2_list.append(cvssv2)
                if cvssv3 != '-':
                    cvssv3_list.append(cvssv3)
    table = table + '</table>'

    #cvssをstr型からfloat型に変更
    cvssv2_float = []
    cvssv3_float = []
    for data_2 in cvssv2_list:
        cvssv2_float.append(float(data_2))
    for data_3 in cvssv3_list:
        cvssv3_float.append(float(data_3))

    #cvss総数カウント 
    total2 = [0, 0, 0, 0]
    total3 = [0, 0, 0, 0]
    for i in cvssv2_float:
        if i >= 9.0:
            total2[0] += 1
        elif i >= 7.0:
            total2[1] += 1
        elif i >= 4.0:
            total2[2] += 1
        else:
            total2[3] += 1
    for i in cvssv3_float:
        if i >= 9.0:
            total3[0] += 1
        elif i >= 7.0:
            total3[1] += 1
        elif i >= 4.0:
            total3[2] += 1
        else:
            total3[3] += 1
    
    #cvssの合計を表示する円グラフを作成
    labels = ["緊急", "重要", "警告", "注意", "なし意"]
    values = total3
    trace = go.Pie(labels=labels, values=values)
    # レイアウト定義
    layout = go.Layout(
        title='円グラフの例'
    )
    fig = go.Figure(data=[trace], layout=layout)
    # グラフを表示
    graph = fig.to_html(full_html=False, default_height=500, default_width=500)
    
    return render_template('search.html', keyword=keyword, response=Markup(table), graph=graph)
