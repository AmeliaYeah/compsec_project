import logging
import json
from datetime import datetime

class SecurityLogger:
	def __init__(self, log_file='logs/security.log'):
		self.logger = logging.getLogger('security')
		self.logger.setLevel(logging.INFO)
		handler = logging.FileHandler(log_file)
		formatter = logging.Formatter(
			'%(asctime)s - %(levelname)s - %(message)s'
		)
		handler.setFormatter(formatter)
		self.logger.addHandler(handler)

	def log_event(self, event_type, user_id, details, ip, UA, severity='INFO'):
		"""Log security event"""
		log_entry = {
			'timestamp': datetime.utcnow().isoformat(),
			'event_type': event_type,
			'user_id': user_id,
			'ip_address': ip,
			'user_agent': UA,
			'details': details,
			'severity': severity
		}
		if severity == 'CRITICAL':
			self.logger.critical(json.dumps(log_entry))
		elif severity == 'ERROR':
			self.logger.error(json.dumps(log_entry))
		elif severity == 'WARNING':
			self.logger.warning(json.dumps(log_entry))
		else:
			self.logger.info(json.dumps(log_entry))