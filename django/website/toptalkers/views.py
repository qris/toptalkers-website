# Create your views here.

import django_tables2 as tables

class TableDataWithOrderingBugFix(tables.tables.TableData):
    def _translate_aliases_to_accessors(self, aliases):
        """
        Translate from order by aliases to column accessors.
        """
        from django_tables2.utils import OrderBy, OrderByTuple
        import itertools
        columns = (self.table.columns[OrderBy(alias).bare] for alias in aliases)
        # columns = (c.accessor for c in columns)
        return OrderByTuple(itertools.chain(*((c.accessor,) for c in columns)))

    	# def order_by(self, aliases):
        """
        Order the data based on order by aliases (prefixed column names) in the
        table.

        :param aliases: optionally prefixed names of columns ('-' indicates
                        descending order) in order of significance with
                        regard to data ordering.
        :type  aliases: :class:`~.utils.OrderByTuple`
        """
        # import pdb; pdb.set_trace()
        accessors = self._translate_aliases_to_accessors(aliases)
        if hasattr(self, 'queryset'):
            translate = lambda accessor: accessor.replace(Accessor.SEPARATOR, QUERYSET_ACCESSOR_SEPARATOR)
            self.queryset = self.queryset.order_by(*(translate(a) for a in accessors))
        else:
            self.list.sort(cmp=accessors.cmp)

class TopTalkers(tables.Table):
	TableDataClass = TableDataWithOrderingBugFix

	rank = tables.Column()
	protocol = tables.Column()
	source_address = tables.Column(accessor='src.textaddr')
	source_port = tables.Column(accessor='src.port')
	dest_address = tables.Column(accessor='dst.textaddr')
	dest_port = tables.Column(accessor='dst.port')
	bytes = tables.Column()
	
	class Meta:
		attrs = {'class': 'paleblue'}    

from django.views.generic import TemplateView

protocolNames = {
	6: 'tcp',
	17: 'udp',
	1: 'icmp',
	50: 'esp'
	}

class TableView(TemplateView):
	template_name = "index.html"
    
	def get_context_data(self, **kwargs):
		context = super(TableView, self).get_context_data(**kwargs)

		from pysnmp.entity.rfc3413.oneliner import cmdgen

		cnfTopFlowsTable = (1,3,6,1,4,1,9,9,387,1,7,8)
		errorIndication, errorStatus, errorIndex, varBinds = \
			cmdgen.CommandGenerator().bulkCmd(
				cmdgen.CommunityData('my-agent', 'AfNOGsnmp', 1),
				cmdgen.UdpTransportTarget(('br01.mtg.afnog.org', 161)),
				0, 1000, cnfTopFlowsTable)

		class Row(object):
			pass

		class Address(object):
			def __str__(self):
				return "%s:%s" % (self.textaddr, self.port)

		if errorIndication is not None:
			raise Exception(errorIndication)
			
		if errorStatus != 0:
			raise Exception(errorStatus)

		talkers = []

		for i, v in enumerate(varBinds):
			# print "%s: %s" % (i, v)
			objectName, objectValue = v[0]
			assert len(objectName) > len(cnfTopFlowsTable)
			# print "%s == %s" % (objectName[:len(cnfTopFlowsTable)], cnfTopFlowsTable)
			# assert objectName[:len(cnfTopFlowsTable)] == cnfTopFlowsTable
			if objectName[:len(cnfTopFlowsTable)] != cnfTopFlowsTable:
				# cisco returns objects that it shouldn't?
				continue
			suffix = objectName[len(cnfTopFlowsTable):]
			# print "%s = %s" % (suffix, objectValue)
	
			rowIndex = suffix[2] - 1
			assert rowIndex <= len(talkers)

			if rowIndex == len(talkers):
				row = Row()
				row.rank = rowIndex + 1
				row.src = Address()
				row.dst = Address()
				row.nh = Address()
				talkers.append(row)
			else:
				row = talkers[rowIndex]
	
			valueType = suffix[1]
	
			if valueType == 2:
				row.src.type = objectValue
			elif valueType == 3:
				row.src.rawaddr = objectValue
			elif valueType == 4:
				row.src.mask = objectValue
			elif valueType == 5:
				row.dst.type = objectValue
			elif valueType == 6:
				row.dst.rawaddr = objectValue
			elif valueType == 7:
				row.dst.mask = objectValue
			elif valueType == 8:
				row.nh.type = objectValue
			elif valueType == 9:
				row.nh.addr = objectValue
			elif valueType == 10:
				row.src.port = objectValue
			elif valueType == 11:
				row.dst.port = objectValue
			elif valueType == 12:
				row.src.asn = objectValue
			elif valueType == 13:
				row.dst.asn = objectValue
			elif valueType == 14:
				row.src.ifindex = objectValue
			elif valueType == 15:
				row.dst.ifindex = objectValue
			elif valueType == 16:
				row.start = objectValue
			elif valueType == 17:
				row.end = objectValue
			elif valueType == 18:
				row.tos = objectValue
			elif valueType == 19:
				row.protonum = objectValue
			elif valueType == 20:
				row.tcpflags = objectValue
			elif valueType == 21:
				row.samplerid = objectValue
			elif valueType == 22:
				row.classid = objectValue
			elif valueType == 23:
				row.flags = objectValue
			elif valueType == 24:
				row.bytes = objectValue
			elif valueType == 25:
				row.packets = objectValue

		for row in talkers:
			for addr in row.src, row.dst:
				if addr.type == 1:
					# import socket
					# addr.textaddr = socket.inet_ntoa(addr.rawaddr)
					addr.textaddr = ".".join("%d" % ord(b) for b in addr.rawaddr)
			
			try:
				row.protocol = protocolNames[row.protonum]
			except KeyError:
				row.protocol = "%d" % row.protonum
				
		table = TopTalkers(talkers)

		from django_tables2 import RequestConfig
		RequestConfig(self.request).configure(table)				

		context['table'] = table
		
		from pygooglechart import PieChart3D
		chart = PieChart3D(500, 200)
		chart.add_data([int(t.bytes) for t in talkers])
		# chart.set_pie_labels(["%s-%s" % (t.src, t.dst) for t in talkers])
		chart.set_pie_labels(["%s" % t.rank for t in talkers])
		context['chart'] = chart.get_url()

		return context
