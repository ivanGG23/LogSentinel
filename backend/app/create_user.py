import getpass
import sys

from .database import Base, SessionLocal, engine
from .models import User
from .security import hash_password


def main():
    if len(sys.argv) != 2:
        print("Uso: python -m app.create_user <usuario>")
        sys.exit(1)
    username = sys.argv[1]
    password = getpass.getpass("Contraseña (mínimo 12 caracteres): ")
    if len(password) < 12:
        sys.exit("La contraseña debe tener al menos 12 caracteres")
    if getpass.getpass("Repite la contraseña: ") != password:
        sys.exit("Las contraseñas no coinciden")
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        db.add(User(username=username, password_hash=hash_password(password)))
        db.commit()
    print(f"Usuario '{username}' creado.")


if __name__ == "__main__":
    main()
