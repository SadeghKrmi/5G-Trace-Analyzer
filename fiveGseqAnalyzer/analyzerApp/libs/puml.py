"""
The purpose of this module is to represent and create PlantUML Sequence Diagrams (http://plantuml.com/sequence-diagram)

This module provides the following:
	- SeqEvent class: a structured representation of any sequence event to be represented in a PlantUML Sequence Diagram
	- SeqDiagram class: a structured representation of a PlantUML Sequence Diagram
"""

SEQEVENT_TYPE_MESSAGE = 'message'

class SeqEvent(object):
	'''
	Represents a sequence event from a PlantUML Sequence Diagram.
	It has the following properties
		- event_type: takes a default value, but can be overridden just in case we want to add some non-message events
		- participants
		- arrow
		- message_lines
		- sequence_number
		- notes
	'''
	def __init__(self, participants, message_lines, arrow=None, timestamp=None, sequence_number=None, notes=None, event_type=SEQEVENT_TYPE_MESSAGE):
		self.event_type = event_type
		self.message_lines = message_lines
		self.participants = participants
		self.arrow = arrow
		self.sequence_number = sequence_number
		self.notes = notes

	def __repr__(self):
		return str({
			'event_type': self.event_type,
			'message_lines': self.message_lines,
			'participants': self.participants,
			'arrow': self.arrow,
			'sequence_number': self.sequence_number,
			'notes': self.notes
		})

class SeqDiagram(object):
	'''
	Represents a PlantUML Sequence Diagram.
	Thus, it has the following properties
		- participants
		- arrow
		- message_lines
		- sequence_number
		- notes
		- event_type: takes a default value, but can be overridden just in case we want to add some non-message events
	'''
	def __init__(self, seqevents, participants=None):
		self.seqevents = seqevents
		self.participants = participants

	def __get_participants_str(participants):
		(src, dst) = participants
		src_participant_str = src['name']
		dst_participant_str = dst['name']
		return (src_participant_str, dst_participant_str)

	def __get_arrow_str(arrow):
		arrow_head = arrow['head']
		arrow_shaft = arrow['shaft']
		arrow_color = arrow.get('color')
		if(arrow_color != None):
			arrow_color_str = '[#{}]'.format(arrow_color)
		else:
			arrow_color_str = ''
		arrow_str = '{}{}{}'.format(arrow_shaft, arrow_color_str, arrow_head)
		return arrow_str

	def __format_message_line(text, color=None, bold=False, underlined=False):
		formatted_str = text
		if(color != None):
			formatted_str = '<font color={}>{}</font>'.format(color, formatted_str)
		if(bold == True):
			formatted_str = '<b>{}</b>'.format(formatted_str)
		if(underlined == True):
			formatted_str = '<u>{}</u>'.format(formatted_str)
		return formatted_str

	def __get_message_line_str(message_line):
		message_line_str = message_line.get('formatted')
		if(message_line_str == None):
			message_line_str = SeqDiagram.__format_message_line(
				message_line['text'], 
				message_line.get('color'), 
				message_line.get('bold'), 
				message_line.get('underlined'))
		return message_line_str

	def __get_sequence_number_str(sequence_number):
		sequence_number_format = sequence_number.get('format')
		if(sequence_number_format == None):
			sequence_number_format = '<b>[Frame [[#]]]</b>'
		return 'autonumber {} 1 "{}"'.format(sequence_number['number'], sequence_number_format)

	def get_puml_lines(self, puml_start_options):
		puml_lines = ['@startuml', '']
		puml_lines.extend(puml_start_options)
		for seqevent in self.seqevents:
			(src_str, dst_str) = SeqDiagram.__get_participants_str(seqevent.participants)
			arrow_str = SeqDiagram.__get_arrow_str(seqevent.arrow)
			message_line_strs = [ SeqDiagram.__get_message_line_str(m) for m in seqevent.message_lines ]
			message_str = '\\n'.join(message_line_strs)
			puml_main_line = '{} {} {}: {}'.format(src_str, arrow_str, dst_str, message_str)
			if(seqevent.sequence_number != None):
				puml_lines.append(SeqDiagram.__get_sequence_number_str(seqevent.sequence_number))
			puml_lines.append(puml_main_line)
			puml_lines.append('')
		puml_lines.append('@enduml')
		return puml_lines
