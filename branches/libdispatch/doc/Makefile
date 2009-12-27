all:
	for diagram in src hier ; do \
	   cat $$diagram.dot | dot -Tpng > $$diagram.png ; \
	done

clean:
	rm *.png
