from tools.utils.logger import get_logger


def test_get_logger():
    logger = get_logger("test")

    assert logger.name == "test"
    assert logger.level > 0
    assert len(logger.handlers) == 2
