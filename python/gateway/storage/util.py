import pika, json



def upload(file, fs, channel, access):
    try:
        fid = fs.put(file)
    except Exception:
        return 'Internal server error', 500
    
    message = {
        'video_fid': str(fid),
        'mp3_fid': None,
        'username': access['username'],
    }

    try:
        channel.basic_publish(
            exchange='',
            routing_key='video_queue',
            body=json.dumps(message),
            properties=pika.BasicProperties(
                delivery_mode=pika.spec.PERSISTENT_DELIVERY_MODE
            )
        )
    except Exception:
        fs.delete(fid)
        return 'Internal server error', 500
