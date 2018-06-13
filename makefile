.PHONY: default
default:
	make sender
	make receiver
sender:
	make -f sender.mk
sender_clean:
	make clean -f sender.mk
receiver:
	make -f receiver.mk
receiver_clean:
	make clean -f receiver.mk
clean:
	make sender_clean
	make receiver_clean

