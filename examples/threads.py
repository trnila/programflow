from threading import Thread
from random import randint
import time


class MyThread(Thread):
	def __init__(self, val):
		Thread.__init__(self)
		self.val = val

	def run(self):
		print("test from " + str(self.val))

if __name__ == '__main__':
	myThreadOb1 = MyThread(1)
	myThreadOb2 = MyThread(2)
	myThreadOb3 = MyThread(3)
	myThreadOb4 = MyThread(4)

	myThreadOb1.start()
	myThreadOb2.start()
	myThreadOb3.start()
	myThreadOb4.start()

	myThreadOb1.join()
	myThreadOb2.join()
	myThreadOb3.join()
	myThreadOb4.join()


	print('Main Terminating...')