from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from scanner.common import DB_PATH, ensure_data_dir

ensure_data_dir()

engine = create_engine(f"sqlite:///{DB_PATH}", connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
