import menu,scan

def firstFunc():
	print 'in first'
	raw_input()

def secondFunc():
	print 'in second'

def thirdFunc():
	print 'in third'

def updateFunction(mainMenu):
	#time.sleep(15)
	print 'updating..'

mainMenu = menu.Menu('DNS Spoofer',update=updateFunction)
options = [{"name":"Scan Network","function":firstFunc},
       {"name":"secondOption","function":secondFunc},
       {"name":"thirdOption","function":thirdFunc}]
mainMenu.addOptions(options)
mainMenu.open()