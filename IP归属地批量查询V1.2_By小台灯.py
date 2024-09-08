import tkinter as tk
from tkinter import messagebox
import requests
import re

def get_screen_dimensions(window):
    # Function to get the screen width and height
    screen_width = window.winfo_screenwidth()
    screen_height = window.winfo_screenheight()
    return screen_width, screen_height


def center_window(window, width, height):
    # Function to center the window on the screen
    screen_width, screen_height = get_screen_dimensions(window)
    x_coordinate = int((screen_width / 2) - (width / 2))
    y_coordinate = int((screen_height / 2) - (height / 2))
    window.geometry(f'{width}x{height}+{x_coordinate}+{y_coordinate}')

def get_ip_list():
    def on_submit():
        ip_list = text.get("1.0", tk.END).strip().split('\n')
        root.ip_list = [ip.strip() for ip in ip_list if ip.strip()]

        if not root.ip_list:
            messagebox.showerror("错误", "请在左边框输入IP地址，一行一个。")
            return

        update_query_result()

    def update_query_result():
        query_result.config(state=tk.NORMAL)
        query_result.delete("1.0", tk.END)

        ip_list = root.ip_list
        print(ip_list)
        selected_queries = [query_var.get() for query_var in query_vars if query_var.get()]

        if any(selected_queries):
            for selected_query in selected_queries:
                if selected_query == "IP138":
                    for ip in root.ip_list:
                        headers = {
                            'Cookie': 'PHPSESSID=t4btovs6a7uervsjjgb297n9s0; Hm_lvt_044a26327cd520af2dc2ed69965e79f8=1721583146; HMACCOUNT=ADA626C1B3FE67EB; Hm_tf_mtjosdlelse=1721583146; Hm_lvt_mtjosdlelse=1721583146; Hm_lpvt_044a26327cd520af2dc2ed69965e79f8=1721660433; Hm_lpvt_mtjosdlelse=1721660433',
                            'Sec-Ch-Ua': '"Chromium";v="123", "Not:A-Brand";v="8"',
                            'Sec-Ch-Ua-Mobile': '?0',
                            'Sec-Ch-Ua-Platform': '"Windows"',
                            'Upgrade-Insecure-Requests': '1',
                            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.122 Safari/537.36',
                            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                            'Sec-Fetch-Site': 'same-origin',
                            'Sec-Fetch-Mode': 'navigate',
                            'Sec-Fetch-User': '?1',
                            'Sec-Fetch-Dest': 'document',
                            'Referer': 'https://www.ipshudi.com/',
                            'Accept-Encoding': 'gzip, deflate, br',
                            'Accept-Language': 'zh-CN,zh;q=0.9',
                            'Priority': 'u=0, i',
                            'Connection': 'close'
                        }
                        url = f'https://ipchaxun.com/{ip}/'
                        try:
                            response = requests.get(url, headers=headers)
                            response.encoding = 'utf-8'
                            # print(response.text)
                            # 从response.text中提取所需信息
                            ip_match = re.search(
                                r'<span class="name">iP地址：</span><span class="value">(\d+\.\d+\.\d+\.\d+)</span>',
                                response.text)
                            # print(ip_match)
                            # 判断是否成功匹配到IP地址
                            if ip_match:
                                ip_address = ip_match.group(1)
                                print(f"IP地址: {ip_address}")
                                location_match = re.search(
                                    r'<span class="name">归属地：</span><span class="value">(.*?)</span>', response.text,
                                    re.S)
                                location = location_match.group(1).strip()
                                location = re.sub(r'<.*?>', ' ', location)  # 去除HTML标签
                                location = re.sub(r'\s+', ' ', location)  # 去除多余空格
                                print(f"归属地: {location}")
                                query_result.insert(tk.END, f'IP地址: {ip_address}\n归属地: {location}\n')
                                operator = re.search(
                                    r'<label><span class="name">运营商：</span><span class="value">(.*?)</span></label>',
                                    response.text)
                                if operator:
                                    operator = operator.group(1)
                                else:
                                    operator = '未找到运营商信息'
                                print(f"运营商: {operator}")
                                query_result.insert(tk.END, f'运营商: {operator}\n')
                                print('--------------------')
                            else:
                                print(f'IP地址: {ip} 不支持查询')
                                query_result.insert(tk.END, f'IP地址: {ip} 不支持查询\n')
                                print('--------------------')
                            query_result.insert(tk.END, '------------------------------\n')
                            # query_result.insert(tk.END, f'--------------------\n')
                        except requests.exceptions.TooManyRedirects:
                            print(f"IP地址: {ip} 请求超出了最大重定向次数，稍后再试。")
                            query_result.insert(tk.END, f'IP地址: {ip} 请求超出了最大重定向次数，稍后再试。\n')
                            print('--------------------')
                            query_result.insert(tk.END, '------------------------------\n')
                            # messagebox.showerror("请求错误", "请求超出了最大重定向次数，请检查URL是否正确。")
                        except requests.exceptions.RequestException as e:
                            print(f"IP地址: {ip} 请求错误。")
                            query_result.insert(tk.END, f'IP地址: {ip} 请求错误。\n')
                            print('--------------------')
                            query_result.insert(tk.END, '------------------------------\n')
                            # messagebox.showerror("请求错误", f"发生了一个错误: {e}")
                        except Exception as e:
                            print(f"IP地址: {ip} 未知错误。")
                            query_result.insert(tk.END, f'IP地址: {ip} 未知错误。\n')
                            print('--------------------')
                            query_result.insert(tk.END, '------------------------------\n')
                            # messagebox.showerror("未知错误", f"发生了一个未知错误: {e}")

                elif selected_query == "IP138pro":
                    for ip in root.ip_list:
                        headers = {
                            "Host": "www.ipshudi.com",
                            "Sec-Ch-Ua": '"Chromium";v="125", "Not.A/Brand";v="24"',
                            "Sec-Ch-Ua-Mobile": "?0",
                            "Sec-Ch-Ua-Platform": '"Windows"',
                            "Upgrade-Insecure-Requests": "1",
                            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.60 Safari/537.36",
                            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                            "Sec-Fetch-Site": "none",
                            "Sec-Fetch-Mode": "navigate",
                            "Sec-Fetch-User": "?1",
                            "Sec-Fetch-Dest": "document",
                            "Accept-Encoding": "gzip, deflate, br",
                            "Accept-Language": "zh-CN,zh;q=0.9",
                            "Priority": "u=0, i",
                            "Connection": "keep-alive"
                        }
                        url = f'https://www.ipshudi.com/{ip}.htm'
                        try:
                            response = requests.get(url, headers=headers)
                            response.encoding = 'utf-8'
                            # print(response.text)
                            # 从response.text中提取所需信息
                            ip_match = re.search(
                                r'<span>(\d+\.\d+\.\d+\.\d+)</span>',
                                response.text)
                            # print(ip_match)
                            # 判断是否成功匹配到IP地址
                            if ip_match:
                                ip_address = ip_match.group(1)
                                print(f"IP地址: {ip_address}")
                                query_result.insert(tk.END, f'IP地址: {ip_address}\n')
                                # 匹配归属地信息
                                location_match = re.search(
                                    r'<td class="th">归属地</td>\s*<td>\s*<span>(.*?)</span>', response.text, re.S)

                                if location_match:
                                    location = location_match.group(
                                        1).strip()  # + " " + location_match.group(2).strip()
                                    location = re.sub(r'<.*?>', ' ', location)  # 去除HTML标签
                                    location = re.sub(r'\s+', ' ', location)  # 去除多余空格
                                    print(f"归属地: {location}")
                                    query_result.insert(tk.END, f'归属地: {location}\n')
                                else:
                                    print("未找到归属地信息")
                                    query_result.insert(tk.END, f'未找到归属地信息\n')
                                operator = re.search(
                                    r'<tr><td class="th">运营商</td><td><span>(.*?)</span></td></tr>',
                                    response.text)
                                if operator:
                                    operator = operator.group(1)
                                else:
                                    operator = '未找到运营商信息'
                                print(f"运营商: {operator}")
                                query_result.insert(tk.END, f'运营商: {operator}\n')
                                operator = re.search(
                                    r'<tr><td class="th">iP类型</td><td><span>(.*?)</span></td></tr>',
                                    response.text)
                                if operator:
                                    operator = operator.group(1)
                                else:
                                    operator = '未找到iP类型'
                                print(f"iP类型: {operator}")
                                query_result.insert(tk.END, f'iP类型: {operator}\n')
                                operator = re.search(
                                    r'<tr><td class="th">标记</td><td><span>(.*?)</span></td></tr>',
                                    response.text)
                                if operator:
                                    operator = operator.group(1)
                                else:
                                    operator = '未找到标记'
                                print(f"标记: {operator}")
                                query_result.insert(tk.END, f'标记: {operator}\n')
                                print('--------------------')
                                query_result.insert(tk.END, '------------------------------\n')
                            else:
                                print(f'IP地址: {ip} 不支持查询')
                                query_result.insert(tk.END, f'IP地址: {ip} 不支持查询\n')
                                print('--------------------')
                                query_result.insert(tk.END, '------------------------------\n')
                        except requests.exceptions.TooManyRedirects:
                            print(f"IP地址: {ip} 请求超出了最大重定向次数，稍后再试。")
                            query_result.insert(tk.END, f'IP地址: {ip} 请求超出了最大重定向次数，稍后再试。\n')
                            print('--------------------')
                            query_result.insert(tk.END, '------------------------------\n')
                            # messagebox.showerror("请求错误", "请求超出了最大重定向次数，请检查URL是否正确。")
                        except requests.exceptions.RequestException as e:
                            print(f"IP地址: {ip} 请求错误。")
                            query_result.insert(tk.END, f'IP地址: {ip} 请求错误。\n')
                            print('--------------------')
                            query_result.insert(tk.END, '------------------------------\n')
                            # messagebox.showerror("请求错误", f"发生了一个错误: {e}")
                        except Exception as e:
                            print(f"IP地址: {ip} 未知错误。")
                            query_result.insert(tk.END, f'IP地址: {ip} 未知错误。\n')
                            print('--------------------')
                            query_result.insert(tk.END, '------------------------------\n')
                            # messagebox.showerror("未知错误", f"发生了一个未知错误: {e}")


                elif selected_query == "站长":
                    def query_ip_batch(ip_list):
                        url = 'https://ip.tool.chinaz.com/ipbatch'
                        headers = {
                            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                            'accept-encoding': 'gzip, deflate, br, zstd',
                            'accept-language': 'zh-CN,zh;q=0.9',
                            'cache-control': 'max-age=0',
                            'content-type': 'application/x-www-form-urlencoded',
                            'cookie': '_clck=alo5ss%7C2%7Cfn9%7C0%7C1649; Hm_lvt_ca96c3507ee04e182fb6d097cb2a1a4c=1724345656; Hm_lvt_ca96c3507ee04e182fb6d097cb2a1a4c=1724345666,1724427013; Hm_lvt_76692581280401051fcab76c6467b290=1724345659,1724427672; toolbox_urls=www.chinaz.com; ucvalidate=a346772f-5d92-62e1-3d3b-20e1e1489fdc; toolUserGrade=DA558BECA59696EB6D6F7073658259097496A34F9B3E8B35F3075E72A88B4A26B934E8591D99CD7E37E991A14C7F29560DBF99836079205BD33B4F487349C2BD0816970F5FFADDA723849156704AEECCC32C47D9DAAB287F2613249314BF5C537FFBE7E646C2F40E0027DFC12CF56B1541AEEF5DA830B256; bbsmax_user=9da91e84-653b-daad-5a70-3013e13f833d; qHistory=aHR0cDovL2lwLnRvb2wuY2hpbmF6LmNvbS9pcGJhdGNoL19JUOaJuemHj+afpeivonxodHRwOi8vdG9vbC5jaGluYXouY29tL3Rvb2xzL3VybGVuY29kZS5hc3B4X1VybEVuY29kZee8lueggS/op6PnoIF8Ly90b29sLmNoaW5hei5jb20vdG9vbHMvaHRtbGVuY29kZS5hc3B4X0hUTUznvJbnoIEv6Kej56CBfC8vdG9vbC5jaGluYXouY29tL3Rvb2xzL25hdl/lt6Xlhbflr7zoiKp8aHR0cDovL2lwLnRvb2wuY2hpbmF6LmNvbS9zaXRlaXAvX0lQ5omA5Zyo5Zyw5om56YeP5p+l6K+ifC8vdG9vbC5jaGluYXouY29tL2JhdGNocXVlcnlf5a6e5pe25om56YeP5p+l6K+ifGh0dHA6Ly9pcC5jaGluYXouY29tL2lwYmF0Y2gvX0lQ5om56YeP5p+l6K+ifC8vaXAuY2hpbmF6LmNvbS9fSVDmn6Xor6J8Ly90b29sLmNoaW5hei5jb20vcG9ydF/nq6/lj6Pmiavmj498Ly90b29sLmNoaW5hei5jb20vaXB2NndlYmNoZWNrX0lQdjbmt7Hluqbmo4DmtYt8Ly90b29sLmNoaW5hei5jb20vaXB2Nl9JUHY25qOA5rWL',
                            'origin': 'https://ip.tool.chinaz.com',
                            'referer': 'https://ip.tool.chinaz.com/ipbatch',
                            'sec-ch-ua': '"Not)A;Brand";v="99", "Google Chrome";v="127", "Chromium";v="127"',
                            'sec-ch-ua-mobile': '?0',
                            'sec-ch-ua-platform': '"Windows"',
                            'sec-fetch-dest': 'document',
                            'sec-fetch-mode': 'navigate',
                            'sec-fetch-site': 'same-origin',
                            'sec-fetch-user': '?1',
                            'upgrade-insecure-requests': '1',
                            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36'
                        }

                        # 将IP列表转换为载荷格式：每个IP以换行符分隔
                        payload = {
                            'ips': '\r\n'.join(ip_list),
                            'submore': '查询'  # 按钮提交的参数，可能会变化
                        }

                        response = requests.post(url, headers=headers, data=payload)

                        if response.status_code == 200:
                            # 返回的页面可能是HTML，需要进行解析
                            result = response.text
                            return result
                        else:
                            print(f"请求失败，状态码: {response.status_code}")
                            return None

                    # IP列表
                    ip_list = root.ip_list
                    # print(ip_list)

                    result = query_ip_batch(ip_list)
                    print(result)
                    def parse_ip_info(html):
                        # 使用正则表达式提取IP地址、数字地址和归属地信息
                        pattern = re.compile(
                            r'<td class="bor-l1s02 bor-b1s oneR">\s*(\d+\.\d+\.\d+\.\d+)\s*</td>'  # 匹配IP地址
                            r'.*?<td class="bor-l1s02 bor-b1s">(\d+)</td>'  # 匹配数字地址
                            r'.*?<td class="bor-l1s02 bor-b1s tl pl10">(.*?)</td>',  # 匹配归属地
                            re.S
                        )

                        matches = pattern.findall(html)

                        result_list = []
                        for match in matches:
                            ip = match[0].strip()
                            number = match[1].strip()
                            location = match[2].strip()

                            # 格式化输出
                            result = f"IP地址：{ip}\n数字地址：{number}\n归属地：{location}\n"
                            result_list.append(result)

                        return "\n".join(result_list)

                    # 调用函数解析并输出结果
                    parsed_result = parse_ip_info(result)
                    print(parsed_result)
                    query_result.insert(tk.END, parsed_result + '\n')

                elif selected_query == "ioc_query":
                    ip_str_ioc = '\n or '.join([f'client_ip="{ip}"' for ip in ip_list])
                    ioc_query = f'\n---------ioc_query---------\nselect * from ioc_log where {ip_str_ioc}'
                    query_result.insert(tk.END, ioc_query + '\n')
        else:
            query_result.insert(tk.END, "请先选择要查询的条件")

        query_result.config(state=tk.DISABLED)

    def create_context_menu(widget):
        menu = tk.Menu(widget, tearoff=0)
        menu.add_command(label="复制", command=lambda: widget.event_generate('<<Copy>>'))
        menu.add_command(label="粘贴", command=lambda: widget.event_generate('<<Paste>>'))
        menu.add_command(label="剪切", command=lambda: widget.event_generate('<<Cut>>'))
        widget.bind("<Button-3>", lambda event: menu.tk_popup(event.x_root, event.y_root))

    def select_all():
        all_selected = select_all_var.get()
        for query_var, query in zip(query_vars, queries):
            query_var.set(query if all_selected else "")

    def clear_fields():
        text.delete("1.0", tk.END)
        query_result.config(state=tk.NORMAL)
        query_result.delete("1.0", tk.END)
        query_result.config(state=tk.DISABLED)

    root = tk.Tk()
    root.title("IP归属地批量查询v1.2-By小台灯")
    root.geometry("900x700")
    # Center the window
    center_window(root, 900, 800)

    # Top frame for IP input and options
    top_frame = tk.Frame(root)
    top_frame.pack(side=tk.TOP, fill=tk.X, padx=10, pady=10)

    input_frame = tk.Frame(top_frame)
    input_frame.pack(side=tk.LEFT, padx=10, pady=10)

    tk.Label(input_frame, text="请输入IP地址，每行一个:").pack(pady=10)
    text = tk.Text(input_frame, height=15, width=70)
    text.pack(side=tk.LEFT)
    create_context_menu(text)

    input_scrollbar = tk.Scrollbar(input_frame)
    input_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    text.config(yscrollcommand=input_scrollbar.set)
    input_scrollbar.config(command=text.yview)

    options_frame = tk.Frame(top_frame)
    options_frame.pack(side=tk.LEFT, padx=10, pady=10)

    # submit_button = tk.Button(options_frame, text="查询", command=on_submit)
    # submit_button.grid(row=0, column=1, padx=(0, 10), pady=20)
    #
    # clear_button = tk.Button(options_frame, text="清空", command=clear_fields)
    # clear_button.grid(row=0, column=2, padx=(10, 0), pady=20)
    # 美化查询按钮
    submit_button = tk.Button(
        options_frame,
        text="查询",
        command=on_submit,
        bg="#4CAF50",  # 背景颜色
        fg="white",  # 字体颜色
        font=("Arial", 12, "bold"),  # 字体样式
        relief="raised",  # 按钮边框样式
        bd=5,  # 边框宽度
        padx=10,  # 内边距
        pady=5  # 内边距
    )
    submit_button.grid(row=0, column=0, padx=(0, 10), pady=20)

    # 美化清空按钮
    clear_button = tk.Button(
        options_frame,
        text="清空",
        command=clear_fields,
        bg="#f44336",  # 背景颜色
        fg="white",  # 字体颜色
        font=("Arial", 12, "bold"),  # 字体样式
        relief="raised",  # 按钮边框样式
        bd=5,  # 边框宽度
        padx=10,  # 内边距
        pady=5  # 内边距
    )
    clear_button.grid(row=0, column=1, padx=(10, 0), pady=20)


    query_vars = []
    queries = ["IP138", "IP138pro",  "站长"]#, "elb_query", "ioc_query"
    display_queries = ["IP138", "IP138pro", "站长"]#, "elb", "ioc"

    # for idx, (query, display_query) in enumerate(zip(queries, display_queries)):
    #     query_var = tk.StringVar()
    #     query_vars.append(query_var)
    #     tk.Checkbutton(options_frame, text=display_query, variable=query_var, onvalue=query, offvalue="").grid(row=1,
    #                                                                                                            column=idx,
    #                                                                                                            padx=5)
    #
    # select_all_var = tk.BooleanVar()
    # tk.Checkbutton(options_frame, text="全选", variable=select_all_var, command=select_all).grid(row=1,
    #                                                                                              column=len(queries),
    #                                                                                              padx=5)
    # 美化复选框
    for idx, (query, display_query) in enumerate(zip(queries, display_queries)):
        query_var = tk.StringVar()
        query_vars.append(query_var)

        checkbutton = tk.Checkbutton(
            options_frame,
            text=display_query,
            variable=query_var,
            onvalue=query,
            offvalue="",
            bg="#f0f0f0",  # 背景颜色
            fg="#333333",  # 字体颜色
            font=("Arial", 12),  # 字体样式
            # selectcolor="#4CAF50",  # 选中时的背景颜色
            activebackground="#e0e0e0",  # 鼠标悬停时的背景颜色
            activeforeground="black"  # 鼠标悬停时的字体颜色
        )
        checkbutton.grid(row=1, column=idx, padx=10, pady=5, sticky='nsew')  # 使用 sticky 参数

    # 美化全选复选框
    select_all_var = tk.BooleanVar()
    select_all_checkbutton = tk.Checkbutton(
        options_frame,
        text="全选",
        variable=select_all_var,
        command=select_all,
        bg="#f0f0f0",  # 背景颜色
        fg="#333333",  # 字体颜色
        font=("Arial", 12),  # 字体样式
        # selectcolor="#4CAF50",  # 选中时的背景颜色
        activebackground="#e0e0e0",  # 鼠标悬停时的背景颜色
        activeforeground="black"  # 鼠标悬停时的字体颜色
    )
    select_all_checkbutton.grid(row=1, column=len(queries), padx=10, pady=5, sticky='nsew')  # 使用 sticky 参数

    # 设置列权重以实现居中对齐
    for i in range(len(queries) + 1):
        options_frame.grid_columnconfigure(i, weight=1)

    # Bottom frame for query results
    result_frame = tk.Frame(root)
    result_frame.pack(side=tk.BOTTOM, fill=tk.BOTH, expand=True, padx=10, pady=10)

    tk.Label(result_frame, text="查询结果:").pack(pady=10)

    query_result = tk.Text(result_frame, height=20, width=110, state=tk.DISABLED)
    query_result.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    create_context_menu(query_result)

    query_scrollbar = tk.Scrollbar(result_frame)
    query_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    query_result.config(yscrollcommand=query_scrollbar.set)
    query_scrollbar.config(command=query_result.yview)

    root.ip_list = []
    root.mainloop()

    return getattr(root, 'ip_list', [])


# 获取IP列表
ips = get_ip_list()
