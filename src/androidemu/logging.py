import logging

JNICALL = logging.INFO + 1
SYSCALL = logging.INFO + 2

logging.addLevelName(JNICALL, 'JNICALL')
logging.addLevelName(SYSCALL, 'SYSCALL')
