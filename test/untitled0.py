# importing required libraries
import mahotas as mh
import numpy as np
import matplotlib.pyplot as plt
    
# creating region
# numpy.ndarray
regions = np.zeros((10, 10), bool)
    
# setting 1 value to the region
regions[1, :2] = 1
regions[5:8, 6: 8] = 1
regions[8, 0] = 1
      
# showing the image with interpolation = 'nearest'
print("Image")
plt.imshow(regions, interpolation ='nearest')
plt.show()
   
# template for hit miss
template = np.array([
            [0, 1, 1],
            [0, 1, 1],
            [0, 1, 1]])
   
# hit miss transform
img = mh.hitmiss(regions, template)
  
# showing image
print("Image after hit miss transform")
plt.imshow(img)
plt.show()