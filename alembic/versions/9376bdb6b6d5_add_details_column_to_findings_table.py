"""add_details_column_to_findings_table

Revision ID: 9376bdb6b6d5
Revises: 19efe4099d72
Create Date: 2025-05-09 14:05:58.701463

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '9376bdb6b6d5' # Replace with actual new revision ID
down_revision: Union[str, None] = '19efe4099d72' # Replace with actual previous revision ID
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('findings', sa.Column('details', sa.JSON(), nullable=True))
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('findings', 'details')
    # ### end Alembic commands ###