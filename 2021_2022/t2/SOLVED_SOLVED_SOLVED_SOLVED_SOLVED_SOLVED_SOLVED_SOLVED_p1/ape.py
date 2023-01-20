#!/usr/bin/python3
from pytablewriter.style import Style
import pandas as pd
import os
from pytablewriter import MarkdownTableWriter

print(os.getcwd())

print(os.environ['END_TIME'])
print(os.environ['START_TIME'])
print(os.environ['GIST_LINK'])
def main():
    csv_data=open("chall_info.csv", "r").read()
    csv_data.replace("dd/mm/yyyy hh:mm:ss", os.environ['END_TIME'])
    csv_data.replace("-", os.environ['GIST_LINK'])
    df = pd.read_csv("chall_info.csv", sep='\t')

    writer = MarkdownTableWriter(dataframe=df, margin=1, theme='altrow')
    writer.set_style(0, Style(align="center"))
    writer.set_style(1, Style(align="center"))
    writer.set_style(2, Style(align="center"))
    writer.set_style(3, Style(align="center"))
    writer.set_style(4, Style(align="center"))
    writer.set_style(5, Style(align="center"))
    a=writer.write_table()
    print(type(a))

if __name__ == "__main__":
    main()