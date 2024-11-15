"""Initial migration

Revision ID: 1dc250624f56
Revises: 6debfebfbecc
Create Date: 2024-04-19 18:13:23.589184

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '1dc250624f56'
down_revision = '6debfebfbecc'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###

    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('payment', sa.Float(), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_column('payment')

    with op.batch_alter_table('sales', schema=None) as batch_op:
        batch_op.create_index('user_id_idx', ['user_id'], unique=False)

    with op.batch_alter_table('merchandise', schema=None) as batch_op:
        batch_op.create_index('catergory_id_idx', ['category_id'], unique=False)

    # ### end Alembic commands ###
