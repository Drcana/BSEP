"""empty message

Revision ID: 20cbca825445
Revises: 
Create Date: 2020-09-10 19:05:50.637359

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '20cbca825445'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('record',
    sa.Column('cert_pk', sa.String(length=48), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=True),
    sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('commonName', sa.String(length=256), nullable=False),
    sa.Column('cert', sa.Binary(), nullable=False),
    sa.PrimaryKeyConstraint('cert_pk')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('record')
    # ### end Alembic commands ###