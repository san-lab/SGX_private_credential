import pika
import json

connection = pika.BlockingConnection(
    pika.ConnectionParameters(host='localhost'))
channel = connection.channel()

channel.queue_declare(queue='hello')

formatedJson = {
	"Credential Request": {
		"type": "Credit Scoring",
		"customerID": 123,
		"SubjecSPublicKey": "-----BEGIN RSA PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs+ZGv20suqeVy+LrA+tr\nhYdov0IQvWLavVw5v383d8rRbnjXxB0UroX+61/9olL0KnYpgCKr+UC+1uf3FuFs\n008DMkKSg8umWrV+8etHPZa31qSBgYWgrlygScAoPU5yQY3x/7NFFaIAs89bCw2J\n5kKcQh/NHk+dRAYuQ4qmo6OKp0TW065MEprpfWZHgc9uynk7fRG+DHyLtGxkjb2J\n6nSPSm7wK8Sb75YZV7orU1R80Brn1zbVxBKheLGfKgc7QK/6SuASlssR4pe58zIi\n/KJtO8CqzpzmJShaxnPlxaUr7GRs3mCnMOL0bUYTkQsqUEfx/imh8PM7eXWuBAOF\nLQIDAQAB\n-----END RSA PUBLIC KEY-----"
	}
}

channel.basic_publish(exchange='', routing_key='hello', body=json.dumps(formatedJson))
print(" [x] Sent 'Hello World!'")
connection.close()