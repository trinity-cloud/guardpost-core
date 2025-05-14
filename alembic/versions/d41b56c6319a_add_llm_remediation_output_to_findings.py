"""add_llm_remediation_output_to_findings

Revision ID: d41b56c6319a
Revises: 9376bdb6b6d5
Create Date: 2025-05-13 12:44:57.428914

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd41b56c6319a'
down_revision: Union[str, None] = '9376bdb6b6d5'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('findings', 
                  sa.Column('llm_remediation_output', sa.JSON(), nullable=True)
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('findings', 'llm_remediation_output')
