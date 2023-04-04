import snap7


client = snap7.client.Client()
client.connect("192.168.1.12", 0, 2)
client.get_connected()
True
data = client.db_read(1, 0, 4)
print(data)
client.db_write(1, 0, data)

data = (ctypes.c_uint8 * size_to_read)()  # In this ctypes array data will be stored.
result = client.as_db_read(1, 0, size_to_read, data)

block = client.get_block_info("DB", 1)
print(block)

client.destroy()
