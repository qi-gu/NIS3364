import tkinter as tk
from tkinter.ttk import *

from scapy.all import Padding, Raw, hexdump

from datetime import datetime

class track_TCP:
	def __init__(self, packets, packet):
		self.root = tk.Tk()
		self.root.geometry('1100x700')
		self.root.title('追踪TCP流')

		self.packet_table = None
		self.packets = self.__handle_packets(packets, packet)
		
		self.main_page()
		self.root.mainloop()

	def __handle_packets(self, packets, packet):
		packets_list = []
		if "IP" in packet:
			src = packet["IP"].src
			dst = packet["IP"].dst
		elif 'IPv6' in packet:
			src = packet['IPv6'].src
			dst = packet['IPv6'].dst
		else:
			src = packet.src
			dst = packet.dst
		sport=packet['TCP'].sport
		dport=packet['TCP'].dport
		
		for p in packets:
			if "TCP" in p:
				if "IP" in p:
					p_src = p["IP"].src
					p_dst = p["IP"].dst
				elif 'IPv6' in packet:
					p_src = packet['IPv6'].src
					p_dst = packet['IPv6'].dst
				else:
					p_src = p.src
					p_dst = p.dst
				
				p_sport=p['TCP'].sport
				p_dport=p['TCP'].dport
				if (src == p_src and dst == p_dst and sport == p_sport and dport == p_dport) or \
					(src == p_dst and dst == p_src and sport == p_dport and dport == p_sport):
					packets_list.append(p)
		return packets_list
	
	def __get_packet_layers(self, packet):
		counter = 0
		while True:
			layer = packet.getlayer(counter)
			if layer is None:
				break
			yield layer
			counter += 1

	def __insert_packets(self):
		for i in range(len(self.packets)):
			packet = self.packets[i]
			index = i + 1
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
	
	def __select_packet(self, _):
		self.packet_tree.delete(*self.packet_tree.get_children())
		self.hex_text.configure(state='normal')
		self.hex_text.delete(1.0, 'end')
		
		idx = self.packet_table.set(self.packet_table.focus())['No']
		packet = self.packets[int(idx) - 1]
		
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
		self.hex_text.insert('end', hexdump(packet, dump=True))
		self.hex_text.configure(state='disabled')
	
	def __main_info(self):
		packet_frame = tk.Frame(self.root, relief='flat', bd=5)
		packet_frame.place(x=0, y=0, relwidth=1, relheight=0.54)

		# 抓包结果
		columns = ['No', 'Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info']
		y_scroll = Scrollbar(packet_frame)
		y_scroll.pack(side='right', fill='y')
		self.packet_table = Treeview(packet_frame, height=6, columns=columns, show='headings', yscrollcommand=y_scroll.set)
		y_scroll['command'] = self.packet_table.yview
		self.packet_table.bind('<<TreeviewSelect>>', self.__select_packet)
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
		self.packet_table.column('Protocol', width=100, minwidth=100, anchor='s')
		self.packet_table.column('Length', width=70, minwidth=70, anchor='s')
		self.packet_table.column('Info', width=270, minwidth=270, anchor='s')
		self.packet_table.place(x=0, y=0, relwidth=0.98, relheight=0.95)

	def __packet_info(self):
		packet_info_frame = tk.Frame(self.root, relief='flat', bd=5)
		packet_info_frame.place(x=0, rely=0.54, relwidth=0.5, relheight=0.45)

		y_scroll = Scrollbar(packet_info_frame)
		y_scroll.pack(side='right', fill='y')
		self.packet_tree = Treeview(packet_info_frame, height=8, show='tree', yscrollcommand=y_scroll.set)
		self.packet_tree.column('#0', stretch=True)
		self.packet_tree.place(relwidth=0.95, relheight=1)
	
	def __packet_hex(self):
		hex_frame = tk.Frame(self.root, relief='flat', bd=5)
		hex_frame.place(relx=0.5, rely=0.54, relwidth=0.5, relheight=0.45)
		
		y_scroll = Scrollbar(hex_frame)
		y_scroll.pack(side='right', fill='y')
		self.hex_text = tk.Text(hex_frame, wrap=tk.WORD, yscrollcommand=y_scroll.set, state='disabled')
		self.hex_text.place(relx=0, rely=0, relwidth=0.95, relheight=1)
		self.hex_text.configure()
		y_scroll['command'] = self.hex_text.yview


	def main_page(self):
		self.__main_info()
		self.__packet_info()
		self.__packet_hex()
		self.__insert_packets()
		
