import sys
from .database import Base, SessionLocal, engine
from .models import Source
from .security import generate_api_key, hash_api_key


def main():
    if len(sys.argv) != 3 or sys.argv[2] not in ("ssh", "web", "nginx"):
        print("Uso: python -m app.create_source <nombre> <ssh|web|nginx>")
        sys.exit(1)
    name, type_ = sys.argv[1], sys.argv[2]
    Base.metadata.create_all(engine)
    key = generate_api_key()
    with SessionLocal() as db:
        db.add(Source(name=name, type=type_, api_key_hash=hash_api_key(key)))
        db.commit()
    print(f"Fuente '{name}' creada.")
    print("API key (guárdala, no se vuelve a mostrar):")
    print(key)


if __name__ == "__main__":
    main()
