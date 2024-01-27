import tkinter as tk
from tkinter import messagebox
from tkinter.font import Font
from tkinter.ttk import *

from scapy.all import get_working_ifaces, AsyncSniffer, threading, Padding, Raw, hexdump
from scapy.arch.common import compile_filter
from scapy.layers import http

from datetime import datetime
from queue import Queue

from merge_ip import merge_IP
from track_tcp import track_TCP

class GUI:
	def __init__(self):
		self.NIC_listbox = None
		self.root = tk.Tk()
		self.root.geometry('1100x700')
		self.root.title('Sniffer')
		self.sniffer = None

		self.NIC_list = get_working_ifaces()
		self.NIC_name = []
		for face in self.NIC_list:
			self.NIC_name.append(face.name)
		self.start_button = None
		self.packet_table = None
		self.packets = []
		self.handling_q = Queue()
		self.handling_thread = []
		self.working = False
		self.filter_content = ''
		self.packet_nums = 0
		
		for i in range(3):
			self.handling_thread.append(threading.Thread(target=self.__thread_packet_analyse, daemon=True))
			self.handling_thread[i].start()
		
		self.start_page()
		self.root.mainloop()

	def __menu_set(self):
		self.mainmenu = tk.Menu(self.root)
		self.filemenu = tk.Menu(self.mainmenu, tearoff=False)
		self.filemenu.add_command(label='介绍', command=lambda: messagebox.showinfo(title='介绍', message='作者：奇古'))
		self.filemenu.add_separator()
		self.filemenu.add_command(label='退出', command=self.root.quit)
		self.mainmenu.add_cascade(label='关于程序', menu=self.filemenu)
		self.root.config(menu=self.mainmenu)

	def __change_page(self, new_page):
		for widget in self.root.winfo_children():
			widget.destroy()
		new_page()

	def __get_packet_layers(self, packet):
		counter = 0
		while True:
			layer = packet.getlayer(counter)
			if layer is None:
				break
			yield layer
			counter += 1

	def __thread_packet_analyse(self):
		while True:
			lock = threading.Lock()
			with lock:
				index, packet = self.handling_q.get()
				packet_time = datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S')
				if 'IP' in packet:
					src = packet['IP'].src
					dst = packet['IP'].dst
				elif 'IPv6' in packet:
					src = packet['IPv6'].src
					dst = packet['IPv6'].dst
				else:
					src = packet.src
					dst = packet.dst
				for tmp in self.__get_packet_layers(packet):
					if not isinstance(tmp, (Padding, Raw)):
						layer = tmp
				if layer.name[0:3] == 'DNS':
					protocol = 'DNS'
				else:
					protocol = layer.name
				length = str(len(packet))
				try:
					info = packet.summary()
				except:
					info = 'Unknown info format'
				items = self.packet_table.insert('', 'end', values=[index, packet_time, src, dst, protocol, length, info])
				self.packet_table.see(items)

	def __packet_analyse(self, packet):
		self.packets.append(packet)
		self.packet_nums += 1
		self.handling_q.put([self.packet_nums, packet])
	
	def __change_sniff(self):
		if self.working:
			self.sniffer.stop()
			self.start_button.configure(bg='white')
			self.start_button.configure(text='开始抓包')
			self.working = False
		else:
			# 清空抓包数据
			self.packet_nums = 0
			self.packets.clear()
			self.packet_tree.delete(*self.packet_tree.get_children())
			self.hex_text.configure(state='normal')
			self.hex_text.delete(1.0, 'end')
			self.hex_text.configure(state='disabled')
			for item in self.packet_table.get_children():
				self.packet_table.delete(item)

			self.sniffer = AsyncSniffer(
				iface=self.iface,
				prn=self.__packet_analyse,
				filter=self.filter_content
			)
			self.sniffer.start()
			self.start_button.configure(bg='red')
			self.start_button.configure(text='停止抓包')
			self.working = True
	
	def __check_filter(self, _):
		self.filter_content = self.filter_entry.get().strip()
		if self.filter_content == '':
			self.filter_entry.configure(bg='white')
			return
		try:
			compile_filter(filter_exp=self.filter_content)
			self.filter_entry.configure(bg='green')
		except:
			self.filter_entry.configure(bg='red')
			self.filter_content = ''
	
	def __select_packet(self, _):
		self.packet_tree.delete(*self.packet_tree.get_children())
		self.hex_text.configure(state='normal')
		self.hex_text.delete(1.0, 'end')
		
		idx = self.packet_table.set(self.packet_table.focus())['No']
		packet = self.packets[int(idx) - 1]
		
		self.hex_text.insert('end', hexdump(packet, dump=True))
		self.hex_text.configure(state='disabled')
		
		layers = []
		layers_num = 0
		while True:
			layer = packet.getlayer(layers_num)
			if layer is None:
				break
			layers.append(layer)
			layers_num += 1

		father_layer = [0] * layers_num
		for index, layer in enumerate(layers):
			father_layer[index] = self.packet_tree.insert('', 'end', text=layer.name)
			for name, value in layer.fields.items():
				self.packet_tree.insert(father_layer[index], 'end', text=f'{name}: {value}')
	
	def __trace_tcp(self):
		idx = self.packet_table.set(self.packet_table.focus())['No']
		packet = self.packets[int(idx) - 1]
		if 'TCP' not in packet:
			messagebox.showerror(title='错误', message='该包不含TCP层')
			return
		threading.Thread(target=track_TCP, args=(self.packets, packet,), daemon=True).start()
	
	def __merge_IP(self):
		threading.Thread(target=merge_IP, args=(self.packets,), daemon=True).start()
	
	def __main_info(self):
		control_frame = tk.Frame(self.root, relief='flat', bd=5)
		packet_frame = tk.Frame(self.root, relief='flat', bd=5)
		control_frame.place(x=0, y=0, relwidth=1, height=40)
		packet_frame.place(x=0, y=40, relwidth=1, relheight=0.48)

		# 按钮
		self.start_button = tk.Button(control_frame, text='开始抓包', command=self.__change_sniff, bg='white')
		self.start_button.place(x=10, y=0)

		# 过滤器输入框
		self.filter_text = tk.Label(control_frame, text='输入捕获过滤器')
		self.filter_entry = tk.Entry(control_frame)
		self.filter_text.place(x=70, y=5)
		self.filter_entry.place(x=160, y=6, width=650, height=20)
		self.filter_entry.bind('<FocusOut>', self.__check_filter)

		# 抓包结果
		columns = ['No', 'Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info']
		y_scroll = Scrollbar(packet_frame)
		y_scroll.pack(side='right', fill='y')
		self.packet_table = Treeview(packet_frame, height=6, columns=columns, show='headings', yscrollcommand=y_scroll.set)
		y_scroll['command'] = self.packet_table.yview
		self.packet_table.bind('<<TreeviewSelect>>', self.__select_packet)
		self.packet_table.bind('<Button-3>', self.packet_menu)
		self.packet_table.heading('No', text='序号')
		self.packet_table.heading('Time', text='时间')
		self.packet_table.heading('Source', text='源地址')
		self.packet_table.heading('Destination', text='目的地址')
		self.packet_table.heading('Protocol', text='协议')
		self.packet_table.heading('Length', text='长度')
		self.packet_table.heading('Info', text='信息')
		self.packet_table.column('No', width=40, minwidth=40, anchor='s')
		self.packet_table.column('Time', width=130, minwidth=130, anchor='s')
		self.packet_table.column('Source', width=120, minwidth=120, anchor='s')
		self.packet_table.column('Destination', width=120, minwidth=120, anchor='s')
		self.packet_table.column('Protocol', width=60, minwidth=60, anchor='s')
		self.packet_table.column('Length', width=70, minwidth=70, anchor='s')
		self.packet_table.column('Info', width=500, minwidth=500, anchor='s')
		self.packet_table.place(x=0, y=0, relwidth=0.98, relheight=0.95)

	def __packet_info(self):
		packet_info_frame = tk.Frame(self.root, relief='flat', bd=5)
		packet_info_frame.place(x=0, rely=0.54, relwidth=0.5, relheight=0.45)

		y_scroll = Scrollbar(packet_info_frame)
		y_scroll.pack(side='right', fill='y')
		self.packet_tree = Treeview(packet_info_frame, height=8, show='tree', yscrollcommand=y_scroll.set)
		y_scroll['command'] = self.packet_tree.yview
		self.packet_tree.column('#0', stretch=True)
		self.packet_tree.place(relwidth=0.95, relheight=1)
	
	def __packet_hex(self):
		hex_frame = tk.Frame(self.root, relief='flat', bd=5)
		hex_frame.place(relx=0.5, rely=0.54, relwidth=0.5, relheight=0.45)
		
		y_scroll = Scrollbar(hex_frame)
		y_scroll.pack(side='right', fill='y')
		self.hex_text = tk.Text(hex_frame, wrap=tk.WORD, yscrollcommand=y_scroll.set, state='disabled')
		self.hex_text.place(relx=0, rely=0, relwidth=0.95, relheight=1)
		self.hex_text.configure(font=Font(size=10))
		y_scroll['command'] = self.hex_text.yview

	def __reset(self):
		self.__change_page(self.start_page)

	def select_NIC(self, _):
		selected_NIC = self.NIC_listbox.get(self.NIC_listbox.curselection())
		self.iface = self.NIC_list[self.NIC_name.index(selected_NIC)]

		self.__change_page(self.main_page)

	def start_page(self):
		self.__menu_set()
		select = tk.Frame(self.root, relief='flat', bd=5)
		select.place(x=0, y=0, relwidth=1, relheight=1)

		tk.Label(select, text='选择监听网卡：').place(x=0, y=0)

		tmp_name = tk.StringVar()
		tmp_name.set(self.NIC_name)
		self.NIC_listbox = tk.Listbox(select, listvariable=tmp_name, height=5)
		self.NIC_listbox.place(x=0, y=20, relwidth=1, relheight=0.95)
		self.NIC_listbox.bind('<Double-Button-1>', self.select_NIC)

	def main_page(self):
		self.__menu_set()
		self.mainmenu.add_command(label='IP分片重组', command=self.__merge_IP)
		self.mainmenu.add_command(label='重选网卡', command=self.__reset)
		self.__main_info()
		self.__packet_info()
		self.__packet_hex()

	def packet_menu(self, event):
		self.menu = tk.Menu(self.root, tearoff=False)
		self.menu.add_command(label='追踪TCP流', command=self.__trace_tcp)
		self.menu.post(event.x_root, event.y_root)


if __name__ == "__main__":
	sniffer = GUI()