from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'uma-chave-secreta-muito-forte'
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'instance', 'database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = "Por favor, faça o login para acessar esta página."
login_manager.login_message_category = "info"

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)

class Aluno(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    idade = db.Column(db.Integer, nullable=False)
    plano = db.Column(db.String(50), nullable=False)
    treinos = db.relationship('Treino', backref='aluno', lazy=True, cascade="all, delete-orphan")

class Treino(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    descricao = db.Column(db.String(200), nullable=False)
    series = db.Column(db.Integer, nullable=False)
    repeticoes = db.Column(db.Integer, nullable=False)
    aluno_id = db.Column(db.Integer, db.ForeignKey('aluno.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard')) 

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard')) 
        else:
            flash('Login falhou. Verifique seu usuário e senha.', 'danger')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Você foi desconectado com sucesso!', 'success')
    return redirect(url_for('login'))
    
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/alunos')
@login_required
def alunos():
    lista_alunos = Aluno.query.order_by(Aluno.nome).all()
    return render_template('alunos.html', alunos=lista_alunos)

@app.route('/aluno/add', methods=['POST'])
@login_required
def add_aluno():
    nome = request.form.get('nome')
    idade = request.form.get('idade')
    plano = request.form.get('plano')

    if nome and idade and plano:
        novo_aluno = Aluno(nome=nome, idade=idade, plano=plano)
        db.session.add(novo_aluno)
        db.session.commit()
        flash('Aluno adicionado com sucesso!', 'success')
    else:
        flash('Todos os campos são obrigatórios!', 'warning')
    return redirect(url_for('alunos'))

@app.route('/aluno/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_aluno(id):
    aluno = Aluno.query.get_or_404(id)
    if request.method == 'POST':
        aluno.nome = request.form.get('nome')
        aluno.idade = request.form.get('idade')
        aluno.plano = request.form.get('plano')
        db.session.commit()
        flash('Aluno atualizado com sucesso!', 'success')
        return redirect(url_for('alunos'))
    return render_template('editar_aluno.html', aluno=aluno)

@app.route('/aluno/delete/<int:id>')
@login_required
def delete_aluno(id):
    aluno = Aluno.query.get_or_404(id)
    db.session.delete(aluno)
    db.session.commit()
    flash('Aluno removido com sucesso!', 'success')
    return redirect(url_for('alunos'))

@app.route('/aluno/<int:aluno_id>/treinos')
@login_required
def treinos(aluno_id):
    aluno = Aluno.query.get_or_404(aluno_id)
    return render_template('treinos.html', aluno=aluno)

@app.route('/aluno/<int:aluno_id>/treino/add', methods=['POST'])
@login_required
def add_treino(aluno_id):
    descricao = request.form.get('descricao')
    series = request.form.get('series')
    repeticoes = request.form.get('repeticoes')

    if descricao and series and repeticoes:
        novo_treino = Treino(descricao=descricao, series=series, repeticoes=repeticoes, aluno_id=aluno_id)
        db.session.add(novo_treino)
        db.session.commit()
        flash('Treino adicionado com sucesso!', 'success')
    else:
        flash('Todos os campos são obrigatórios!', 'warning')
    return redirect(url_for('treinos', aluno_id=aluno_id))

@app.route('/treino/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_treino(id):
    treino = Treino.query.get_or_404(id)
    if request.method == 'POST':
        treino.descricao = request.form.get('descricao')
        treino.series = request.form.get('series')
        treino.repeticoes = request.form.get('repeticoes')
        db.session.commit()
        flash('Treino atualizado com sucesso!', 'success')
        return redirect(url_for('treinos', aluno_id=treino.aluno_id))
    return render_template('editar_treino.html', treino=treino)

@app.route('/treino/delete/<int:id>')
@login_required
def delete_treino(id):
    treino = Treino.query.get_or_404(id)
    aluno_id = treino.aluno_id
    db.session.delete(treino)
    db.session.commit()
    flash('Treino removido com sucesso!', 'success')
    return redirect(url_for('treinos', aluno_id=aluno_id))

def create_initial_user():
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            hashed_password = bcrypt.generate_password_hash('senha123').decode('utf-8')
            admin_user = User(username='admin', password=hashed_password)
            db.session.add(admin_user)
            db.session.commit()
            print("Usuário 'admin' criado com senha 'senha123'")

if __name__ == '__main__':
    create_initial_user()
    app.run(debug=True)