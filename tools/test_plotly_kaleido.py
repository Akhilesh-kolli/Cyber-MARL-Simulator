import sys
import traceback

print('Python executable:', sys.executable)
try:
    import plotly.express as px
    import plotly
    print('Plotly version:', plotly.__version__)
except Exception as e:
    print('Failed to import plotly:', e)
    raise

fig = px.pie(values=[10, 20, 30], names=['a', 'b', 'c'], title='kaleido test')

# First try with explicit kaleido engine
try:
    b = fig.to_image(format='png', engine='kaleido', width=800, height=450, scale=2)
    print('kaleido export OK, bytes:', len(b))
except Exception as e:
    print('kaleido export failed:', repr(e))
    traceback.print_exc()
    # fallback
    try:
        b2 = fig.to_image(format='png', width=800, height=450, scale=2)
        print('fallback export OK, bytes:', len(b2))
    except Exception as e2:
        print('fallback also failed:', repr(e2))
        traceback.print_exc()
        raise
